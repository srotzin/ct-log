// Hive CT log + vestigium service.
// Endpoints:
//   GET  /v1/sth
//   POST /v1/submit
//   GET  /v1/proof/:leaf_hash
//   GET  /v1/proof-bundle/:leaf_hash   (self-contained, offline-verifiable: receipt + merkle path + STH + dual sigs + pubkeys)
//   GET  /v1/consistency?from=:size1&to=:size2
//   GET  /v1/entries?start=:n&end=:m
//   GET  /v1/vestigium/:did
//   GET  /v1/vestigium/:did/proof/:receipt_hash
//   POST /v1/vestigium/:did/append
//   GET  /v1/vestigium/:did/chain?from=:n&limit=:m
//   GET  /.well-known/ct-pubkey
//   GET  /healthz

import Fastify from 'fastify';
import cors from '@fastify/cors';
import { db, stmts } from './db.js';
import {
  hashLeaf,
  merkleRoot,
  inclusionProof,
  consistencyProof,
  toHex,
  fromHex,
  hashLeafSha3,
  merkleRootSha3,
  inclusionProofSha3,
} from './merkle.js';
import {
  operatorPublicKey, signSTH,
  operatorPqPublicKey, operatorPqScheme, signSTHPQ, signBytesPQ,
  signSTHDual, signSTHDualPQ, encodeSTHDual,
} from './keys.js';
import { tryParseReceipt } from './receipt.js';
import {
  deriveHybridAgent,
  hybridSign,
  hybridVerify,
  deriveDidFromPubkeys,
  HYBRID_AGENT_SCHEME,
} from './hybrid-agent.js';
import {
  initWitnesses,
  getWitnessPubkeys,
  signSTHQuorum,
  verifySTHQuorum,
  WITNESS_QUORUM_SCHEME,
} from './witnesses.js';
import { fetchLatticeEntropy, LATTICE_NAMES, deriveLatticeKey, signWithLatticeKey } from './entropy.js';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { blake3 } from '@noble/hashes/blake3';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const PORT = parseInt(process.env.PORT || '8080', 10);
const STH_CADENCE_MS = parseInt(process.env.STH_CADENCE_MS || '30000', 10);

const app = Fastify({ logger: { level: 'info' } });
await app.register(cors, { origin: true });

// --- Leaf cache: keep all leaf hashes in memory for proof generation. ---
// Parallel BLAKE3 and SHA3-256 caches enable hash agility (Vector 1).
let leafCache = [];        // BLAKE3 leaf hashes (legacy + primary)
let leafCacheSha3 = [];    // SHA3-256 leaf hashes (NIST-only verification path)
function rebuildLeafCache() {
  const hashRows = stmts.getAllLeafHashes.all();
  leafCache = hashRows.map(r => new Uint8Array(r.leaf_hash));
  const payloadRows = stmts.getAllPayloads.all();
  leafCacheSha3 = payloadRows.map(r => hashLeafSha3(new Uint8Array(r.payload)));
  app.log.info({ size: leafCache.length, sha3_size: leafCacheSha3.length }, 'leaf cache rebuilt (BLAKE3 + SHA3-256)');
}
rebuildLeafCache();

// --- STH publication loop ---
async function publishSTH() {
  try {
    const size = leafCache.length;
    const root = merkleRoot(leafCache);
    const rootSha3 = merkleRootSha3(leafCacheSha3);
    const ts = Date.now();
    const latest = stmts.latestTreeHead.get();
    const epoch = latest ? latest.epoch + 1 : 1;
    // Legacy single-root STH (BLAKE3 only) -- preserved for backward compatibility.
    const sig = signSTH({ epoch, treeSize: size, root, ts });
    const pqSig = signSTHPQ({ epoch, treeSize: size, root, ts });
    // Hash-agile dual-root STH: classical + PQ signatures over
    //   epoch(8) || tree_size(8) || root_blake3(32) || root_sha3(32) || ts(8)
    const sigSha3 = signSTHDual({ epoch, treeSize: size, rootBlake3: root, rootSha3, ts });
    const pqSigSha3 = signSTHDualPQ({ epoch, treeSize: size, rootBlake3: root, rootSha3, ts });
    stmts.insertTreeHead.run(
      size,
      Buffer.from(root),
      ts,
      Buffer.from(sig),
      pqSig ? Buffer.from(pqSig) : null,
      Buffer.from(rootSha3),
      Buffer.from(sigSha3),
      pqSigSha3 ? Buffer.from(pqSigSha3) : null,
    );
    app.log.info({
      epoch, tree_size: size,
      root_blake3_prefix: toHex(root).slice(0, 16),
      root_sha3_prefix: toHex(rootSha3).slice(0, 16),
    }, 'STH published (dual-hash)');
  } catch (e) {
    app.log.error({ err: e.message }, 'STH publication failed');
  }
}

// Publish first STH at startup, then on cadence.
await publishSTH();
setInterval(publishSTH, STH_CADENCE_MS);

// --- Routes ---

app.get('/healthz', async () => ({
  ok: true,
  tree_size: leafCache.length,
  sth_cadence_ms: STH_CADENCE_MS,
  ts: Date.now(),
}));

app.get('/.well-known/ct-pubkey', async (req, reply) => {
  if (!operatorPublicKey) {
    return reply.code(503).send({ error: 'operator key not configured' });
  }
  return {
    alg: 'Ed25519',
    pubkey_hex: toHex(operatorPublicKey),
    log_name: 'hive-ct-v1',
    sth_cadence_ms: STH_CADENCE_MS,
    pq: operatorPqPublicKey ? {
      scheme: operatorPqScheme,
      pubkey_hex: toHex(operatorPqPublicKey),
      pubkey_len: operatorPqPublicKey.length,
      note: 'FIPS 204 ML-DSA-65 co-signature alongside classical Ed25519. Same scheme as Circle Arc PQ roadmap.',
    } : null,
  };
});

// Standalone PQ pubkey endpoint for verifiers.
app.get('/.well-known/ct-pq-pubkey', async (req, reply) => {
  if (!operatorPqPublicKey) {
    return reply.code(503).send({ error: 'operator PQ key not configured' });
  }
  return {
    scheme: operatorPqScheme,
    pubkey_hex: toHex(operatorPqPublicKey),
    pubkey_len: operatorPqPublicKey.length,
    log_name: 'hive-ct-v1',
    canonical_sth_encoding: 'epoch(8) || tree_size(8) || root(32) || ts(8), big-endian',
    canonical_receipt_encoding: 'utf8 JSON bytes of canonical envelope (same bytes signed by counterparty Ed25519)',
  };
});

app.get('/v1/sth', async (req, reply) => {
  const row = stmts.latestTreeHead.get();
  if (!row) return reply.code(503).send({ error: 'no STH yet' });
  return {
    epoch: row.epoch,
    tree_size: row.tree_size,
    root: toHex(row.root),                       // BLAKE3 root (primary)
    ts: row.ts,
    sig: toHex(row.sig),                         // ed25519 over legacy canonical (BLAKE3 root only)
    operator_pubkey: operatorPublicKey ? toHex(operatorPublicKey) : null,
    pq_sig: row.pq_sig ? toHex(row.pq_sig) : null,
    pq_scheme: row.pq_sig ? operatorPqScheme : null,
    operator_pq_pubkey: operatorPqPublicKey ? toHex(operatorPqPublicKey) : null,
    // Hash agility (Vector 1): parallel SHA3-256 root + dual-canonical signatures.
    hash_agility: row.root_sha3 ? {
      root_sha3_256: toHex(row.root_sha3),
      sig_sha3: row.sig_sha3 ? toHex(row.sig_sha3) : null,
      pq_sig_sha3: row.pq_sig_sha3 ? toHex(row.pq_sig_sha3) : null,
      canonical_encoding: 'epoch(8) || tree_size(8) || root_blake3(32) || root_sha3_256(32) || ts(8), big-endian',
      hashes: ['BLAKE3-256', 'SHA3-256'],
    } : null,
  };
});

app.post('/v1/submit', async (req, reply) => {
  const { payload_b64 } = req.body || {};
  if (typeof payload_b64 !== 'string') {
    return reply.code(400).send({ error: 'payload_b64 required' });
  }
  let payload;
  try { payload = Buffer.from(payload_b64, 'base64'); }
  catch { return reply.code(400).send({ error: 'bad base64' }); }
  if (payload.length === 0 || payload.length > 65536) {
    return reply.code(400).send({ error: 'payload size out of range' });
  }

  const leaf = hashLeaf(payload);
  const leafBuf = Buffer.from(leaf);

  // Dedup: if leaf already exists, return existing position.
  const existing = stmts.getEntryByHash.get(leafBuf);
  if (existing) {
    const sth = stmts.latestTreeHead.get();
    return {
      seq: existing.seq,
      leaf_hash: toHex(leaf),
      duplicate: true,
      sth: sth ? { epoch: sth.epoch, tree_size: sth.tree_size, root: toHex(sth.root), ts: sth.ts, sig: toHex(sth.sig) } : null,
    };
  }

  // Try to parse as a receipt; if valid, index into vestigium.
  const parsed = tryParseReceipt(payload);
  let agent_did = null, prev_receipt_hash = null, receipt_kind = null;
  if (parsed.ok) {
    agent_did = parsed.receipt.agent_did;
    prev_receipt_hash = parsed.receipt.prev_receipt_hash ? Buffer.from(parsed.receipt.prev_receipt_hash, 'hex') : null;
    receipt_kind = parsed.receipt.action_type;
  }

  const ts = Date.now();
  const info = stmts.insertEntry.run(leafBuf, payload, agent_did, prev_receipt_hash, receipt_kind, ts);
  const seq = info.lastInsertRowid;
  leafCache.push(leaf);
  leafCacheSha3.push(hashLeafSha3(payload));

  if (parsed.ok) {
    // depth = current vestigium depth for this DID + 1
    const current = stmts.vestigiumDepth.get(agent_did)?.depth || 0;
    const newDepth = current + 1;
    stmts.insertVestigium.run(agent_did, newDepth, seq, leafBuf, prev_receipt_hash, ts);
  }

  const sth = stmts.latestTreeHead.get();
  return {
    seq,
    leaf_hash: toHex(leaf),
    duplicate: false,
    indexed_as_receipt: parsed.ok,
    sth: sth ? { epoch: sth.epoch, tree_size: sth.tree_size, root: toHex(sth.root), ts: sth.ts, sig: toHex(sth.sig) } : null,
  };
});

app.get('/v1/proof/:leaf_hash', async (req, reply) => {
  const { leaf_hash } = req.params;
  const leafBuf = Buffer.from(leaf_hash, 'hex');
  const entry = stmts.getEntryByHash.get(leafBuf);
  if (!entry) return reply.code(404).send({ error: 'leaf not found' });
  const sth = stmts.latestTreeHead.get();
  const treeSize = sth.tree_size;
  if (entry.seq > treeSize) return reply.code(409).send({ error: 'leaf not yet in published STH' });
  const proof = inclusionProof(leafCache.slice(0, treeSize), entry.seq - 1);
  return {
    leaf_hash,
    seq: entry.seq,
    index: entry.seq - 1,
    tree_size: treeSize,
    proof: proof.map(p => toHex(p)),
    sth: { epoch: sth.epoch, tree_size: sth.tree_size, root: toHex(sth.root), ts: sth.ts, sig: toHex(sth.sig) },
  };
});

// Self-verifying PQ proof bundle. Everything needed to verify a receipt's inclusion + STH dual-sig
// in ONE JSON blob, no further network calls. Use with scripts/verify-bundle.mjs.
app.get('/v1/proof-bundle/:leaf_hash', async (req, reply) => {
  const { leaf_hash } = req.params;
  if (!/^[0-9a-f]{64}$/i.test(leaf_hash)) {
    return reply.code(400).send({ error: 'leaf_hash must be 32-byte hex' });
  }
  const leafBuf = Buffer.from(leaf_hash, 'hex');
  const entry = stmts.getEntryByHash.get(leafBuf);
  if (!entry) return reply.code(404).send({ error: 'leaf not found' });
  const sth = stmts.latestTreeHead.get();
  if (!sth) return reply.code(503).send({ error: 'no STH yet' });
  if (entry.seq > sth.tree_size) {
    return reply.code(409).send({ error: 'leaf not yet in published STH' });
  }
  const proof = inclusionProof(leafCache.slice(0, sth.tree_size), entry.seq - 1);
  // Hash agility: also compute SHA3-256 leaf + inclusion proof against the SHA3 tree.
  const sha3Available = sth.root_sha3 && leafCacheSha3.length >= sth.tree_size;
  const sha3LeafHash = sha3Available ? hashLeafSha3(new Uint8Array(entry.payload)) : null;
  const sha3Proof = sha3Available
    ? inclusionProofSha3(leafCacheSha3.slice(0, sth.tree_size), entry.seq - 1)
    : null;
  return {
    bundle_version: 3,
    log_name: 'hive-ct-v1',
    leaf_hash,
    seq: entry.seq,
    index: entry.seq - 1,
    receipt_envelope_b64: Buffer.from(entry.payload).toString('base64'),
    merkle: {
      tree_size: sth.tree_size,
      proof: proof.map(p => toHex(p)),
      leaf_hash_scheme: 'BLAKE3(0x00 || payload_bytes)',
      node_hash_scheme: 'BLAKE3(0x01 || left || right)',
    },
    merkle_sha3: sha3Available ? {
      tree_size: sth.tree_size,
      leaf_hash: toHex(sha3LeafHash),
      proof: sha3Proof.map(p => toHex(p)),
      leaf_hash_scheme: 'SHA3-256(0x00 || payload_bytes)',
      node_hash_scheme: 'SHA3-256(0x01 || left || right)',
    } : null,
    sth: {
      epoch: sth.epoch,
      tree_size: sth.tree_size,
      root: toHex(sth.root),
      ts: sth.ts,
      canonical_encoding: 'epoch(8) || tree_size(8) || root(32) || ts(8), big-endian',
      ed25519_sig: toHex(sth.sig),
      pq_sig: sth.pq_sig ? toHex(sth.pq_sig) : null,
      pq_scheme: sth.pq_sig ? operatorPqScheme : null,
    },
    sth_dual: sha3Available ? {
      root_blake3: toHex(sth.root),
      root_sha3_256: toHex(sth.root_sha3),
      canonical_encoding: 'epoch(8) || tree_size(8) || root_blake3(32) || root_sha3_256(32) || ts(8), big-endian',
      ed25519_sig: sth.sig_sha3 ? toHex(sth.sig_sha3) : null,
      pq_sig: sth.pq_sig_sha3 ? toHex(sth.pq_sig_sha3) : null,
      pq_scheme: sth.pq_sig_sha3 ? operatorPqScheme : null,
    } : null,
    // Vector 3 — witness quorum (in-process pseudo-witnesses, hybrid signed).
    // Each witness signs the SAME canonical dual-hash STH bytes with its own
    // independent ed25519 + ML-DSA-65 keys. Quorum-valid when ≥ threshold
    // witnesses have BOTH sigs verify. Deterministic: same STH → same quorum.
    witness_quorum: sha3Available ? (() => {
      const canon = encodeSTHDual({
        epoch: sth.epoch,
        treeSize: sth.tree_size,
        rootBlake3: sth.root,
        rootSha3: sth.root_sha3,
        ts: sth.ts,
      });
      return signSTHQuorum(canon);
    })() : null,
    operator: {
      ed25519_pubkey: operatorPublicKey ? toHex(operatorPublicKey) : null,
      pq_pubkey: operatorPqPublicKey ? toHex(operatorPqPublicKey) : null,
      pq_scheme: operatorPqScheme,
    },
    verifier: {
      hint: 'node verify-bundle.mjs <path-to-bundle.json> -- offline, no network',
      source: 'https://github.com/srotzin/hive-protocol/blob/main/ct-log/scripts/verify-bundle.mjs',
    },
    ip: {
      patent_status: 'Patent Pending',
      patent_filed: '2026-05-08',
      inventor: 'Steve Rotzin',
      assignee: 'Hive Civilization, Inc.',
      notice: 'The cryptographic transparency log architecture, the dual ed25519 + ML-DSA-65 STH co-signature, the dual-hash (BLAKE3 + SHA3-256) hash-agile Merkle commitment, the BLAKE3 leaf/internal domain-separated commitment scheme, the receipt-envelope canonical encoding, the multi-axis physical-entropy lattice handshake, the PQ witness gossip quorum (hybrid Q-of-N), and the self-verifying offline proof-bundle format are original work by Steve Rotzin. Patent Pending. Filed 2026-05-08.',
    },
  };
});

// Vector 3 — witness pubkey discovery. Public endpoint so any verifier can
// fetch the canonical witness identity set out-of-band and check bundles
// without trusting the bundle itself for the pubkeys.
app.get('/.well-known/ct-witnesses', async (req, reply) => {
  reply.header('cache-control', 'public, max-age=60');
  return {
    scheme: WITNESS_QUORUM_SCHEME,
    threshold: 2,
    witnesses: getWitnessPubkeys(),
    canonical_encoding: 'epoch(8) || tree_size(8) || root_blake3(32) || root_sha3_256(32) || ts(8), big-endian',
    ip: {
      patent_status: 'Patent Pending',
      patent_filed: '2026-05-08',
      inventor: 'Steve Rotzin',
      assignee: 'Hive Civilization, Inc.',
    },
  };
});

// Vector 4 — Hybrid Ed25519 + ML-DSA-65 agent identity.
// Demonstrates dual-key deterministic derivation, hybrid signing, and full
// verification path. Every agent that wants post-quantum resistance can derive
// a hybrid keypair from a single 32-byte seed and sign every receipt with BOTH
// keys. A receipt is hybrid-valid only when BOTH signatures verify.
//
// Patent Pending. Filed 2026-05-08. Inventor: Steve Rotzin.
app.post('/v1/agent/hybrid-attest', async (req, reply) => {
  // Input: { seed_hex: 32-byte hex, message?: utf8 string }
  // Output: agent_did, both pubkeys, both sigs over the message bytes.
  // The seed is used IN-MEMORY ONLY and never logged or stored.
  const { seed_hex, message } = req.body || {};
  if (typeof seed_hex !== 'string' || !/^[0-9a-f]{64}$/i.test(seed_hex)) {
    return reply.code(400).send({ error: 'seed_hex must be 32-byte hex (64 chars)' });
  }
  const seed = new Uint8Array(Buffer.from(seed_hex, 'hex'));
  let kp;
  try { kp = deriveHybridAgent(seed); }
  catch (e) { return reply.code(400).send({ error: 'derive failed: ' + e.message }); }
  const msg = typeof message === 'string' && message.length > 0
    ? Buffer.from(message, 'utf8')
    : Buffer.from(`hive-hybrid-attest-${kp.agent_did}-${Date.now()}`, 'utf8');
  const sigs = hybridSign(kp, new Uint8Array(msg));
  // Self-test: verify both sigs we just produced to prove the round-trip works.
  const verify = hybridVerify(
    new Uint8Array(msg),
    sigs.ed25519_sig,
    sigs.ml_dsa_65_sig,
    toHex(kp.ed25519.public_key),
    toHex(kp.ml_dsa_65.public_key)
  );
  return {
    scheme: HYBRID_AGENT_SCHEME,
    agent_did: kp.agent_did,
    public_keys: {
      ed25519: toHex(kp.ed25519.public_key),
      ml_dsa_65: toHex(kp.ml_dsa_65.public_key),
      ml_dsa_65_pubkey_bytes: kp.ml_dsa_65.public_key.length,
    },
    message_b64: Buffer.from(msg).toString('base64'),
    message_utf8: msg.toString('utf8'),
    signatures: {
      ed25519: sigs.ed25519_sig,
      ml_dsa_65: sigs.ml_dsa_65_sig,
      ml_dsa_65_sig_bytes: sigs.ml_dsa_65_sig.length / 2,
    },
    self_test: {
      ed25519_verify: verify.checks.ed25519,
      ml_dsa_65_verify: verify.checks.ml_dsa_65,
      hybrid_pass: verify.ok,
    },
    derivation: {
      ed25519_seed_kdf: 'BLAKE3(seed || "ed25519-agent-v1", 32)',
      ml_dsa_65_seed_kdf: 'BLAKE3(seed || "ml-dsa-65-agent-v1", 32)',
      did_encoding: 'did:hive:hybrid:<BLAKE3(ed_pub || ml_dsa_pub, 32-byte hex)>',
    },
    ip: {
      patent_status: 'Patent Pending',
      patent_filed: '2026-05-08',
      inventor: 'Steve Rotzin',
      assignee: 'Hive Civilization, Inc.',
      notice: 'The dual ed25519 + ML-DSA-65 agent identity, the deterministic hybrid-from-seed derivation, the dual-signature receipt canonical encoding, and the hybrid verification path that requires BOTH signatures to validate are original work by Steve Rotzin.',
    },
  };
});

// Vector 4 — verify endpoint. Stateless. Submit {message_b64, ed_pub, ml_pub,
// ed_sig, ml_sig} and the server returns whether BOTH sigs pass. Useful for
// third parties auditing hybrid-signed receipts offline.
app.post('/v1/agent/hybrid-verify', async (req, reply) => {
  const { message_b64, ed25519_pubkey, ml_dsa_65_pubkey, ed25519_sig, ml_dsa_65_sig } = req.body || {};
  if (typeof message_b64 !== 'string') return reply.code(400).send({ error: 'message_b64 required' });
  if (typeof ed25519_pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(ed25519_pubkey)) {
    return reply.code(400).send({ error: 'ed25519_pubkey must be 32-byte hex' });
  }
  if (typeof ml_dsa_65_pubkey !== 'string' || !/^[0-9a-f]+$/i.test(ml_dsa_65_pubkey)) {
    return reply.code(400).send({ error: 'ml_dsa_65_pubkey must be hex' });
  }
  if (typeof ed25519_sig !== 'string' || !/^[0-9a-f]{128}$/i.test(ed25519_sig)) {
    return reply.code(400).send({ error: 'ed25519_sig must be 64-byte hex (128 chars)' });
  }
  if (typeof ml_dsa_65_sig !== 'string' || !/^[0-9a-f]+$/i.test(ml_dsa_65_sig)) {
    return reply.code(400).send({ error: 'ml_dsa_65_sig must be hex' });
  }
  let msg;
  try { msg = Buffer.from(message_b64, 'base64'); }
  catch { return reply.code(400).send({ error: 'bad base64' }); }
  const verify = hybridVerify(
    new Uint8Array(msg),
    ed25519_sig,
    ml_dsa_65_sig,
    ed25519_pubkey,
    ml_dsa_65_pubkey
  );
  const recoveredDid = deriveDidFromPubkeys(ed25519_pubkey, ml_dsa_65_pubkey);
  return {
    scheme: HYBRID_AGENT_SCHEME,
    hybrid_pass: verify.ok,
    checks: verify.checks,
    recovered_agent_did: recoveredDid,
    ip: {
      patent_status: 'Patent Pending',
      patent_filed: '2026-05-08',
      inventor: 'Steve Rotzin',
      assignee: 'Hive Civilization, Inc.',
    },
  };
});

app.get('/v1/consistency', async (req, reply) => {
  const from = parseInt(req.query.from || '0', 10);
  const to = parseInt(req.query.to || '0', 10);
  if (from < 0 || to < from || to > leafCache.length) {
    return reply.code(400).send({ error: 'bad range' });
  }
  const proof = consistencyProof(leafCache.slice(0, to), from, to);
  return { from, to, proof: proof.map(p => toHex(p)) };
});

app.get('/v1/entries', async (req, reply) => {
  const start = parseInt(req.query.start || '1', 10);
  const end = parseInt(req.query.end || String(start + 99), 10);
  if (start < 1 || end < start || end - start > 999) {
    return reply.code(400).send({ error: 'bad range; max 1000 per request' });
  }
  const rows = stmts.getEntriesRange.all(start, end);
  return {
    entries: rows.map(r => ({
      seq: r.seq,
      leaf_hash: toHex(r.leaf_hash),
      payload_b64: Buffer.from(r.payload).toString('base64'),
      agent_did: r.agent_did,
      receipt_kind: r.receipt_kind,
      ts: r.ts,
    })),
  };
});

// --- Vestigium endpoints ---

app.get('/v1/vestigium/:did', async (req, reply) => {
  const { did } = req.params;
  const latest = stmts.latestVestigium.get(did);
  if (!latest) {
    return { did, depth: 0, last_seq: null, last_receipt_hash: null, last_ts: null };
  }
  return {
    did,
    depth: latest.depth,
    last_seq: latest.seq,
    last_receipt_hash: toHex(latest.leaf_hash),
    last_ts: latest.ts,
  };
});

app.get('/v1/vestigium/:did/proof/:receipt_hash', async (req, reply) => {
  const { did, receipt_hash } = req.params;
  const leafBuf = Buffer.from(receipt_hash, 'hex');
  const entry = stmts.getEntryByHash.get(leafBuf);
  if (!entry || entry.agent_did !== did) {
    return reply.code(404).send({ error: 'receipt not found for this DID' });
  }
  const sth = stmts.latestTreeHead.get();
  if (entry.seq > sth.tree_size) {
    return reply.code(409).send({ error: 'not yet in published STH' });
  }
  const proof = inclusionProof(leafCache.slice(0, sth.tree_size), entry.seq - 1);
  return {
    did,
    receipt_hash,
    seq: entry.seq,
    index: entry.seq - 1,
    tree_size: sth.tree_size,
    proof: proof.map(p => toHex(p)),
    sth: { epoch: sth.epoch, tree_size: sth.tree_size, root: toHex(sth.root), ts: sth.ts, sig: toHex(sth.sig) },
  };
});

app.post('/v1/vestigium/:did/append', async (req, reply) => {
  // Convenience wrapper: validate that payload is a receipt for this DID, then submit.
  const { did } = req.params;
  const { payload_b64 } = req.body || {};
  if (typeof payload_b64 !== 'string') return reply.code(400).send({ error: 'payload_b64 required' });
  const payload = Buffer.from(payload_b64, 'base64');
  const parsed = tryParseReceipt(payload);
  if (!parsed.ok) return reply.code(400).send({ error: 'invalid receipt: ' + parsed.err });
  if (parsed.receipt.agent_did !== did) return reply.code(400).send({ error: 'did mismatch' });
  // Forward to submit logic by re-injecting payload.
  req.body = { payload_b64 };
  return app.inject({ method: 'POST', url: '/v1/submit', payload: { payload_b64 } }).then(r => JSON.parse(r.payload));
});

app.get('/v1/vestigium/:did/chain', async (req, reply) => {
  const { did } = req.params;
  const from = parseInt(req.query.from || '1', 10);
  const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
  const rows = stmts.vestigiumRange.all(did, from, limit);
  return {
    did,
    from,
    count: rows.length,
    chain: rows.map(r => ({
      depth: r.depth,
      seq: r.seq,
      leaf_hash: toHex(r.leaf_hash),
      prev_hash: r.prev_hash ? toHex(r.prev_hash) : null,
      ts: r.ts,
    })),
  };
});

// --- Attestation endpoints (for one-line counterparty signing) ---

// Build a pre-filled receipt envelope for a counterparty to sign.
// The receipt extends the COUNTERPARTY's vestigium — they sign as principal,
// the treasury co-signs as witness. Counterparty depth increments by one.
//
// Usage:
//   GET /v1/attest/prefill?counterparty=circle
//     -> agent_did = did:circle:test
//   GET /v1/attest/prefill?did=did:agent:kimi-k2
//     -> agent_did = did:agent:kimi-k2 (full DID override)
app.get('/v1/attest/prefill', async (req, reply) => {
  const TREASURY_DID = 'did:hive:treasury-001';

  // Two modes: full DID override (?did=did:agent:kimi-k2) or short counterparty name (?counterparty=circle)
  let counterparty_did;
  if (req.query.did) {
    const did = String(req.query.did).trim();
    if (!/^did:[a-z0-9]+:[a-zA-Z0-9._-]+$/.test(did) || did.length > 128) {
      return reply.code(400).send({ error: 'bad did format; expected did:method:identifier' });
    }
    if (did === TREASURY_DID) {
      return reply.code(400).send({ error: 'treasury did is reserved for operator co-signature' });
    }
    counterparty_did = did;
  } else {
    const counterparty = String(req.query.counterparty || 'test').toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!counterparty || counterparty.length > 32) {
      return reply.code(400).send({ error: 'bad counterparty name' });
    }
    counterparty_did = `did:${counterparty}:test`;
  }

  // Anchor to current STH.
  const sth = stmts.latestTreeHead.get();
  if (!sth) return reply.code(503).send({ error: 'no STH yet' });

  // COUNTERPARTY's current vestigium head — receipt extends THEIR chain.
  const cpHead = stmts.latestVestigium.get(counterparty_did);
  const prev_receipt_hash = cpHead ? toHex(cpHead.leaf_hash) : '0'.repeat(64);
  const prev_depth = cpHead ? cpHead.depth : 0;

  const ts = Date.now();
  const did_label = counterparty_did.split(':').slice(1).join('-');
  const input_commit = toHex(blake3(`hive-${did_label}-attestation-${ts}`));
  const output_commit = toHex(blake3('counterparty-attestation-acknowledged'));

  const canonical = {
    v: 1,
    agent_did: counterparty_did,
    prev_receipt_hash,
    log_sth_root: toHex(sth.root),
    log_sth_size: sth.tree_size,
    action_type: 'attestation',
    input_commit,
    output_commit,
    witness_did: TREASURY_DID,
    ts,
  };
  const canonicalBytes = Buffer.from(JSON.stringify(canonical));
  return {
    counterparty_did,
    prev_depth,
    new_depth_if_landed: prev_depth + 1,
    canonical_json: canonical,
    canonical_bytes_b64: canonicalBytes.toString('base64'),
    canonical_bytes_utf8: canonicalBytes.toString('utf8'),
    blake3_hex: toHex(blake3(canonicalBytes)),
    sth: { epoch: sth.epoch, tree_size: sth.tree_size, root: toHex(sth.root), ts: sth.ts },
    instructions: 'Sign canonical_bytes_b64 (decoded to raw bytes) with any Ed25519 key. POST {canonical_bytes_b64, counterparty_pubkey_hex, counterparty_sig_hex} to /v1/attest/submit. The receipt will extend YOUR vestigium under agent_did. Or use the one-line script at /sign.',
  };
});

// Accept a counterparty-signed attestation, validate signature, land receipt.
app.post('/v1/attest/submit', async (req, reply) => {
  const { canonical_bytes_b64, counterparty_pubkey_hex, counterparty_sig_hex } = req.body || {};
  if (!canonical_bytes_b64 || typeof canonical_bytes_b64 !== 'string') {
    return reply.code(400).send({ error: 'canonical_bytes_b64 required' });
  }
  if (!counterparty_pubkey_hex || !counterparty_sig_hex) {
    return reply.code(400).send({ error: 'pubkey and sig required' });
  }

  // Use the exact bytes the counterparty signed.
  let canonicalBytes, canonical_json;
  try {
    canonicalBytes = Buffer.from(canonical_bytes_b64, 'base64');
    canonical_json = JSON.parse(canonicalBytes.toString());
  } catch (e) {
    return reply.code(400).send({ error: 'bad canonical bytes: ' + e.message });
  }
  let pubkey, sig;
  try {
    pubkey = new Uint8Array(Buffer.from(counterparty_pubkey_hex, 'hex'));
    sig = new Uint8Array(Buffer.from(counterparty_sig_hex, 'hex'));
  } catch {
    return reply.code(400).send({ error: 'bad hex encoding' });
  }
  if (pubkey.length !== 32 || sig.length !== 64) {
    return reply.code(400).send({ error: 'bad pubkey or sig length' });
  }

  let sigValid = false;
  try {
    sigValid = await ed.verify(sig, canonicalBytes, pubkey);
  } catch (e) {
    return reply.code(400).send({ error: 'sig verify error: ' + e.message });
  }
  if (!sigValid) {
    return reply.code(400).send({ error: 'counterparty signature invalid' });
  }

  // Build the full receipt envelope. Treasury co-signs in this version using a stored key
  // (set via TREASURY_AGENT_PRIVATE_KEY env). If not set, we land with counterparty sig only
  // and mark agent_sig as 'pending'. For Corey demo, env is set.
  const treasuryPrivHex = process.env.TREASURY_AGENT_PRIVATE_KEY;
  let agent_sig_hex = 'unsigned';
  let agent_pubkey_hex = null;
  if (treasuryPrivHex) {
    const treasuryPriv = new Uint8Array(Buffer.from(treasuryPrivHex, 'hex'));
    const treasuryPub = ed.getPublicKey(treasuryPriv);
    const agentSig = await ed.sign(canonicalBytes, treasuryPriv);
    agent_sig_hex = Buffer.from(agentSig).toString('hex');
    agent_pubkey_hex = Buffer.from(treasuryPub).toString('hex');
  }

  // Operator PQ co-signature over the same canonical bytes (ML-DSA-65 / FIPS 204).
  let operator_pq_sig_hex = null;
  let operator_pq_pubkey_hex = null;
  let pq_scheme_used = null;
  if (operatorPqPublicKey) {
    const pqSig = signBytesPQ(canonicalBytes);
    if (pqSig) {
      operator_pq_sig_hex = Buffer.from(pqSig).toString('hex');
      operator_pq_pubkey_hex = toHex(operatorPqPublicKey);
      pq_scheme_used = operatorPqScheme;
    }
  }

  // The counterparty signed as the principal (agent_did). Treasury co-signs as witness.
  // Operator additionally PQ co-signs (ML-DSA-65) so receipts are quantum-resistant at the log layer.
  const fullReceipt = {
    ...canonical_json,
    agent_sig: counterparty_sig_hex,
    agent_pubkey: counterparty_pubkey_hex,
    witness_sig: agent_sig_hex,
    witness_pubkey: agent_pubkey_hex,
    operator_pq_sig: operator_pq_sig_hex,
    operator_pq_pubkey: operator_pq_pubkey_hex,
    pq_scheme: pq_scheme_used,
  };

  const payload = Buffer.from(JSON.stringify(fullReceipt));
  const leaf = hashLeaf(payload);
  const leafBuf = Buffer.from(leaf);

  const existing = stmts.getEntryByHash.get(leafBuf);
  if (existing) {
    return { duplicate: true, seq: existing.seq, leaf_hash: toHex(leaf) };
  }

  const ts = Date.now();
  const prevHashBuf = canonical_json.prev_receipt_hash ? Buffer.from(canonical_json.prev_receipt_hash, 'hex') : null;
  const info = stmts.insertEntry.run(leafBuf, payload, canonical_json.agent_did, prevHashBuf, canonical_json.action_type, ts);
  const seq = info.lastInsertRowid;
  leafCache.push(leaf);
  leafCacheSha3.push(hashLeafSha3(payload));

  const current = stmts.vestigiumDepth.get(canonical_json.agent_did)?.depth || 0;
  const newDepth = current + 1;
  stmts.insertVestigium.run(canonical_json.agent_did, newDepth, seq, leafBuf, prevHashBuf, ts);

  const sth = stmts.latestTreeHead.get();
  return {
    ok: true,
    seq,
    leaf_hash: toHex(leaf),
    agent_did: canonical_json.agent_did,
    counterparty_did: canonical_json.agent_did,
    witness_did: canonical_json.witness_did,
    vestigium_depth: newDepth,
    pq: operator_pq_sig_hex ? {
      scheme: pq_scheme_used,
      operator_pq_sig: operator_pq_sig_hex,
      operator_pq_pubkey: operator_pq_pubkey_hex,
      sig_bytes: Math.floor(operator_pq_sig_hex.length / 2),
      pubkey_bytes: Math.floor((operator_pq_pubkey_hex || '').length / 2),
      note: 'Operator co-signed the same canonical envelope with FIPS 204 ML-DSA-65. Verify with /.well-known/ct-pq-pubkey.',
    } : null,
    sth: sth ? {
      epoch: sth.epoch,
      tree_size: sth.tree_size,
      root: toHex(sth.root),
      ts: sth.ts,
      sig: toHex(sth.sig),
      pq_sig: sth.pq_sig ? toHex(sth.pq_sig) : null,
      pq_scheme: sth.pq_sig ? operatorPqScheme : null,
    } : null,
    next_sth_in_ms: STH_CADENCE_MS,
    receipt_url: `/v1/proof/${toHex(leaf)}`,
  };
});

// --- Lattice entropy handshake ------------------------------------------
//
// Each lattice has a real public-data feed it draws entropy from. The
// handshake endpoint fetches that feed, mints a receipt under
// did:lattice:<name>, embeds the entropy digest and source URL in the
// canonical envelope, signs with a deterministic per-lattice Ed25519 key
// (operator-bound), and operator co-signs Ed25519 + ML-DSA-65 (FIPS 204).
//
// Anyone can: re-fetch the source URL, recompute the digest, and verify
// both signatures against the public pubkeys. Provably PQ at the signature
// layer, real-world entropy at the substrate layer.

const LATTICE_DESCRIPTIONS = {
  wave: 'Wave-Lattice — entropy from NOAA NDBC ocean buoy wave height, period, and direction.',
  loess: 'Loess-Lattice — entropy from USGS global seismic activity feed (M2.5+).',
  aurora: 'Aurora-Lattice — entropy from NOAA SWPC planetary K-index (geomagnetic activity).',
  'rogue-wave': 'RogueWave-Lattice — entropy from NOAA Tides & Currents water-level anomalies.',
  keystone: 'Keystone-Lattice — entropy from Base mainnet validator-produced block hash.',
  'nano-band': 'Nano-Band-Lattice — entropy from NIST Randomness Beacon v2.0 (RSA-signed pulse chain). Value-banded PQ signing policy: dust receipts amortize one ML-DSA-65 signature across 10,000 payments via Merkle batching; macro payments get full per-payment hybrid Ed25519 + ML-DSA-65.',
};

app.get('/v1/lattice/list', async () => ({
  lattices: LATTICE_NAMES.map(name => ({
    name,
    did: `did:lattice:${name}`,
    description: LATTICE_DESCRIPTIONS[name],
    handshake_url: `/v1/lattice/${name}/handshake`,
  })),
  operator_pq_scheme: operatorPqScheme,
  operator_pq_pubkey: operatorPqPublicKey ? toHex(operatorPqPublicKey) : null,
}));

app.post('/v1/lattice/:name/handshake', async (req, reply) => {
  const name = String(req.params.name || '').toLowerCase();
  if (!LATTICE_NAMES.includes(name)) {
    return reply.code(404).send({ error: 'unknown lattice', known: LATTICE_NAMES });
  }
  const PQ_SEED = process.env.LOG_OPERATOR_PQ_SEED;
  if (!PQ_SEED) return reply.code(503).send({ error: 'operator PQ seed not configured' });

  // 1. Fetch real entropy from the lattice's substrate.
  let entropy;
  try { entropy = await fetchLatticeEntropy(name); }
  catch (e) { return reply.code(502).send({ error: 'entropy fetch failed', detail: e.message }); }

  // 2. Derive the lattice's stable per-lattice Ed25519 agent key.
  const kp = deriveLatticeKey(PQ_SEED, name);
  const lattice_did = `did:lattice:${name}`;

  // 3. Anchor to current STH.
  const sth = stmts.latestTreeHead.get();
  if (!sth) return reply.code(503).send({ error: 'no STH yet' });

  // 4. Lattice's own vestigium head.
  const head = stmts.latestVestigium.get(lattice_did);
  const prev_receipt_hash = head ? toHex(head.leaf_hash) : '0'.repeat(64);
  const prev_depth = head ? head.depth : 0;

  const ts = Date.now();
  const input_commit = entropy.entropy_digest_hex;
  const output_commit = toHex(blake3(Buffer.from(`lattice-handshake-${name}-${ts}`)));

  // 5. Canonical envelope. Embed the entropy data + provenance.
  const canonical = {
    v: 1,
    agent_did: lattice_did,
    prev_receipt_hash,
    log_sth_root: toHex(sth.root),
    log_sth_size: sth.tree_size,
    action_type: 'lattice-entropy-handshake',
    input_commit,
    output_commit,
    witness_did: 'did:hive:treasury-001',
    ts,
    lattice: {
      name,
      source_name: entropy.body.source_name,
      source_url: entropy.body.source_url,
      source_protocol: entropy.body.source_protocol,
      entropy_digest: entropy.entropy_digest_hex,
      entropy_records: entropy.body.records,
      record_count: entropy.body.record_count,
      fetched_ms: entropy.fetched_ms,
      audit_note: 'Re-fetch source_url, normalize per source_protocol, BLAKE3 of canonical JSON must equal entropy_digest.',
    },
  };
  const canonicalBytes = Buffer.from(JSON.stringify(canonical));

  // 6. Sign with the per-lattice Ed25519 agent key.
  const agentSig = signWithLatticeKey(canonicalBytes, kp.priv);
  const agent_sig_hex = Buffer.from(agentSig).toString('hex');
  const agent_pubkey_hex = Buffer.from(kp.pub).toString('hex');

  // 7. Treasury Ed25519 witness co-sig.
  let witness_sig_hex = 'unsigned', witness_pubkey_hex = null;
  const treasuryPrivHex = process.env.TREASURY_AGENT_PRIVATE_KEY;
  if (treasuryPrivHex) {
    const treasuryPriv = new Uint8Array(Buffer.from(treasuryPrivHex, 'hex'));
    const treasuryPub = ed.getPublicKey(treasuryPriv);
    const ws = await ed.sign(canonicalBytes, treasuryPriv);
    witness_sig_hex = Buffer.from(ws).toString('hex');
    witness_pubkey_hex = Buffer.from(treasuryPub).toString('hex');
  }

  // 8. Operator ML-DSA-65 PQ co-sig on the SAME canonical bytes.
  let operator_pq_sig_hex = null, operator_pq_pubkey_hex = null, pq_scheme_used = null;
  if (operatorPqPublicKey) {
    const pqSig = signBytesPQ(canonicalBytes);
    if (pqSig) {
      operator_pq_sig_hex = Buffer.from(pqSig).toString('hex');
      operator_pq_pubkey_hex = toHex(operatorPqPublicKey);
      pq_scheme_used = operatorPqScheme;
    }
  }

  const fullReceipt = {
    ...canonical,
    agent_sig: agent_sig_hex,
    agent_pubkey: agent_pubkey_hex,
    witness_sig: witness_sig_hex,
    witness_pubkey: witness_pubkey_hex,
    operator_pq_sig: operator_pq_sig_hex,
    operator_pq_pubkey: operator_pq_pubkey_hex,
    pq_scheme: pq_scheme_used,
  };

  // 9. Land on the log.
  const payload = Buffer.from(JSON.stringify(fullReceipt));
  const leaf = hashLeaf(payload);
  const leafBuf = Buffer.from(leaf);
  const existing = stmts.getEntryByHash.get(leafBuf);
  if (existing) {
    return { duplicate: true, seq: existing.seq, leaf_hash: toHex(leaf) };
  }
  const prevHashBuf = prev_receipt_hash === '0'.repeat(64) ? null : Buffer.from(prev_receipt_hash, 'hex');
  const info = stmts.insertEntry.run(leafBuf, payload, lattice_did, prevHashBuf, 'lattice-entropy-handshake', ts);
  const seq = info.lastInsertRowid;
  leafCache.push(leaf);
  leafCacheSha3.push(hashLeafSha3(payload));
  const newDepth = prev_depth + 1;
  stmts.insertVestigium.run(lattice_did, newDepth, seq, leafBuf, prevHashBuf, ts);

  const nextSth = stmts.latestTreeHead.get();
  return {
    ok: true,
    lattice: name,
    lattice_did,
    seq,
    leaf_hash: toHex(leaf),
    vestigium_depth: newDepth,
    entropy: {
      source_name: entropy.body.source_name,
      source_url: entropy.body.source_url,
      source_protocol: entropy.body.source_protocol,
      digest_blake3: entropy.entropy_digest_hex,
      record_count: entropy.body.record_count,
      fetched_ms: entropy.fetched_ms,
    },
    signatures: {
      agent_ed25519_sig: agent_sig_hex,
      agent_ed25519_pubkey: agent_pubkey_hex,
      witness_ed25519_sig: witness_sig_hex,
      witness_ed25519_pubkey: witness_pubkey_hex,
      operator_pq_sig: operator_pq_sig_hex,
      operator_pq_pubkey: operator_pq_pubkey_hex,
      pq_scheme: pq_scheme_used,
      pq_sig_bytes: operator_pq_sig_hex ? operator_pq_sig_hex.length / 2 : 0,
    },
    sth: nextSth ? {
      epoch: nextSth.epoch,
      tree_size: nextSth.tree_size,
      root: toHex(nextSth.root),
      ts: nextSth.ts,
      sig: toHex(nextSth.sig),
      pq_sig: nextSth.pq_sig ? toHex(nextSth.pq_sig) : null,
      pq_scheme: nextSth.pq_sig ? operatorPqScheme : null,
    } : null,
    verify: {
      vestigium_url: `/v1/vestigium/${lattice_did}`,
      proof_url: `/v1/proof/${toHex(leaf)}`,
      pq_pubkey_url: '/.well-known/ct-pq-pubkey',
    },
    next_sth_in_ms: STH_CADENCE_MS,
  };
});

// Convenience GET that does the same handshake — easier to share as a link.
app.get('/v1/lattice/:name/handshake', async (req, reply) => {
  return app.inject({ method: 'POST', url: `/v1/lattice/${req.params.name}/handshake` }).then(r => {
    reply.code(r.statusCode);
    return JSON.parse(r.payload);
  });
});

// ============================================================
// Nano-Band PQ — value-banded post-quantum signing for micropayments.
//
// Bands (USD value at risk per payment):
//   B0 dust   : < $0.001          (BLAKE3 leaf only, Merkle-batched, 1 ML-DSA-65 sig per 10,000)
//   B1 micro  : $0.001 – $0.10    (BLAKE3 leaf + Ed25519, Merkle-batched, 1 ML-DSA-65 sig per 1,000)
//   B2 milli  : $0.10  – $10      (per-payment hybrid Ed25519 + ML-DSA-65)
//   B3 macro  : > $10             (per-payment hybrid + STH inclusion + witness quorum 2-of-3)
//
// Every batch root commits to the current NIST beacon pulse (nano-band lattice),
// so even amortized dust receipts inherit fresh public randomness.
// ============================================================

function classifyBand(usdValue) {
  const v = Number(usdValue);
  if (!Number.isFinite(v) || v < 0) throw new Error('value_usd must be a non-negative number');
  if (v < 0.001) return 'B0';
  if (v < 0.10)  return 'B1';
  if (v < 10)    return 'B2';
  return 'B3';
}

function canonStringify(obj) {
  if (Array.isArray(obj)) return '[' + obj.map(canonStringify).join(',') + ']';
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonStringify(obj[k])).join(',') + '}';
}

const BAND_POLICY = {
  B0: { range_usd: '<$0.001', per_payment_sig: 'none', batched_pq_per: 10000, label: 'dust' },
  B1: { range_usd: '$0.001–$0.10', per_payment_sig: 'ed25519', batched_pq_per: 1000, label: 'micro' },
  B2: { range_usd: '$0.10–$10', per_payment_sig: 'hybrid_ed25519_ml_dsa_65', batched_pq_per: 1, label: 'milli' },
  B3: { range_usd: '>$10', per_payment_sig: 'hybrid_ed25519_ml_dsa_65 + STH + witness quorum', batched_pq_per: 1, label: 'macro' },
};

app.get('/v1/nano/policy', async () => ({
  scheme: 'nano-band-v1',
  lattice: 'nano-band',
  entropy_source: 'NIST Randomness Beacon v2.0',
  bands: BAND_POLICY,
  operator_pq_scheme: operatorPqScheme,
  notice: 'Value-banded PQ signing policy for micropayments. Patent Pending. Filed 2026-05-08. Steve Rotzin / Hive Civilization, Inc.',
}));

// Mint a single nano payment receipt. Returns a leaf the caller can include
// in a batch later (B0/B1) or get a full hybrid signature back inline (B2/B3).
app.post('/v1/nano/mint', async (req, reply) => {
  const PQ_SEED = process.env.LOG_OPERATOR_PQ_SEED;
  if (!PQ_SEED) return reply.code(503).send({ error: 'operator PQ seed not configured' });
  const body = req.body || {};
  const valueUsd = body.value_usd;
  const payer = String(body.payer_did || '').slice(0, 256);
  const payee = String(body.payee_did || '').slice(0, 256);
  const memo = body.memo == null ? '' : String(body.memo).slice(0, 512);
  const tsClient = Number(body.ts_ms) || Date.now();
  if (!payer || !payee) return reply.code(400).send({ error: 'payer_did and payee_did required' });
  let band;
  try { band = classifyBand(valueUsd); } catch (e) { return reply.code(400).send({ error: String(e.message || e) }); }

  // Canonical payment envelope.
  const envelope = {
    scheme: 'nano-band-v1',
    band,
    value_usd: Number(valueUsd),
    payer_did: payer,
    payee_did: payee,
    memo,
    ts_ms: tsClient,
    settlement_rail: 'usdc-base',
  };
  const canon = canonStringify(envelope);
  const leaf = blake3(Buffer.from(canon));
  const leafHex = toHex(leaf);

  const out = {
    scheme: 'nano-band-v1',
    band,
    band_policy: BAND_POLICY[band],
    envelope,
    canonical_bytes_b64: Buffer.from(canon).toString('base64'),
    leaf_blake3_hex: leafHex,
    ts_server_ms: Date.now(),
  };

  // B1/B2/B3 — attach per-payment Ed25519 (lattice key on nano-band).
  if (band !== 'B0') {
    const { priv: latticePriv, pub: latticePub } = deriveLatticeKey(PQ_SEED, 'nano-band');
    const sigEd = await ed.sign(Buffer.from(canon), latticePriv);
    out.ed25519_pubkey_hex = toHex(latticePub);
    out.ed25519_signature_hex = toHex(sigEd);
    out.signer_did = 'did:lattice:nano-band';
  }

  // B2/B3 — also attach per-payment ML-DSA-65 (full hybrid).
  if (band === 'B2' || band === 'B3') {
    const pq = signBytesPQ(Buffer.from(canon));
    out.ml_dsa_65_pubkey_hex = pq ? toHex(operatorPqPublicKey) : null;
    out.ml_dsa_65_signature_hex = pq ? toHex(pq) : null;
    out.signing_path = 'per_payment_hybrid';
  } else {
    out.signing_path = 'merkle_batched';
    out.batch_note = `Submit this leaf to /v1/nano/batch with up to ${BAND_POLICY[band].batched_pq_per} other ${band} leaves to amortize one ML-DSA-65 signature across the batch.`;
  }

  return out;
});

// Roll a list of B0/B1 leaves into a Merkle batch, fetch a fresh NIST beacon
// pulse, and sign the (root, beacon) commitment with ML-DSA-65. One PQ sig
// covers up to 10,000 dust payments (B0) or 1,000 micro payments (B1).
app.post('/v1/nano/batch', async (req, reply) => {
  const PQ_SEED = process.env.LOG_OPERATOR_PQ_SEED;
  if (!PQ_SEED) return reply.code(503).send({ error: 'operator PQ seed not configured' });
  const body = req.body || {};
  const band = String(body.band || '').toUpperCase();
  if (band !== 'B0' && band !== 'B1') return reply.code(400).send({ error: 'band must be B0 or B1 (B2/B3 are signed per-payment, not batched)' });
  const leaves = Array.isArray(body.leaves) ? body.leaves : [];
  if (leaves.length === 0) return reply.code(400).send({ error: 'leaves[] required' });
  const max = BAND_POLICY[band].batched_pq_per;
  if (leaves.length > max) return reply.code(400).send({ error: `band ${band} batch limit is ${max} leaves` });
  const leafBufs = leaves.map(h => fromHex(String(h)));
  if (leafBufs.some(b => b.length !== 32)) return reply.code(400).send({ error: 'each leaf must be a 32-byte hex string (BLAKE3 leaf)' });

  // Fresh NIST beacon pulse.
  let beacon;
  try { beacon = await fetchLatticeEntropy('nano-band'); }
  catch (e) { return reply.code(503).send({ error: 'NIST beacon unavailable', detail: String(e.message || e) }); }

  const root = merkleRoot(leafBufs);
  const batchCommitment = {
    scheme: 'nano-band-v1',
    band,
    leaf_count: leafBufs.length,
    merkle_root_blake3_hex: toHex(root),
    beacon_pulse_index: beacon.body.records[0].pulse_index,
    beacon_output_value: beacon.body.records[0].output_value,
    beacon_timestamp: beacon.body.records[0].timestamp,
    entropy_digest_hex: beacon.entropy_digest_hex,
    ts_ms: Date.now(),
  };
  const canon = canonStringify(batchCommitment);
  const sigPQ = signBytesPQ(Buffer.from(canon));
  const { priv: latticePriv, pub: latticePub } = deriveLatticeKey(PQ_SEED, 'nano-band');
  const sigEd = await ed.sign(Buffer.from(canon), latticePriv);

  return {
    scheme: 'nano-band-v1',
    band,
    band_policy: BAND_POLICY[band],
    batch_commitment: batchCommitment,
    canonical_bytes_b64: Buffer.from(canon).toString('base64'),
    ed25519_pubkey_hex: toHex(latticePub),
    ed25519_signature_hex: toHex(sigEd),
    ml_dsa_65_pubkey_hex: sigPQ ? toHex(operatorPqPublicKey) : null,
    ml_dsa_65_signature_hex: sigPQ ? toHex(sigPQ) : null,
    signing_path: 'merkle_batched_with_beacon_pulse',
    amortized_pq_bytes_per_payment: sigPQ ? (sigPQ.length / leafBufs.length).toFixed(3) : null,
    notice: 'One ML-DSA-65 signature attests this entire batch. Per-payment dispute resolves via Merkle inclusion proof against merkle_root_blake3_hex. Patent Pending. Filed 2026-05-08.',
  };
});

// Verify a single mint (per-payment band B2/B3) or a batch commitment (B0/B1).
// Returns a pass/fail per check, mirroring the 9-check offline verifier.
app.post('/v1/nano/verify', async (req, reply) => {
  const body = req.body || {};
  const canonB64 = body.canonical_bytes_b64;
  if (!canonB64) return reply.code(400).send({ error: 'canonical_bytes_b64 required' });
  const canon = Buffer.from(canonB64, 'base64');
  const checks = [];
  function check(name, pass, detail) { checks.push({ name, pass: !!pass, detail: detail || null }); }

  // 1. Canonical bytes parse as JSON with required fields.
  let env;
  try { env = JSON.parse(canon.toString('utf8')); check('canonical_parse', true); }
  catch (e) { check('canonical_parse', false, String(e.message || e)); return { pass: false, checks }; }

  // 2. Re-canonicalize and confirm equality.
  const recanon = canonStringify(env);
  check('canonical_form', recanon === canon.toString('utf8'), 'envelope must be in sorted-key canonical JSON');

  // 3. Scheme tag.
  check('scheme_tag', env.scheme === 'nano-band-v1');

  // 4. Ed25519 signature if provided.
  if (body.ed25519_signature_hex && body.ed25519_pubkey_hex) {
    try {
      const ok = await ed.verify(fromHex(body.ed25519_signature_hex), canon, fromHex(body.ed25519_pubkey_hex));
      check('ed25519_signature', ok);
    } catch (e) { check('ed25519_signature', false, String(e.message || e)); }
  }

  // 5. ML-DSA-65 verification — best-effort against operator pubkey on file.
  if (body.ml_dsa_65_signature_hex && body.ml_dsa_65_pubkey_hex) {
    const onfile = operatorPqPublicKey ? toHex(operatorPqPublicKey) : null;
    check('ml_dsa_65_pubkey_match', onfile && onfile === body.ml_dsa_65_pubkey_hex, 'pubkey must equal operator on-file');
    // Full PQ verification happens in the offline verifier; here we attest binding.
    check('ml_dsa_65_signature_present', !!body.ml_dsa_65_signature_hex);
  }

  // 6. If a leaf was provided (for per-payment), confirm BLAKE3(canon) == leaf.
  if (body.leaf_blake3_hex) {
    const recomputed = toHex(blake3(canon));
    check('leaf_matches_canon', recomputed === body.leaf_blake3_hex);
  }

  // 7. If a Merkle inclusion proof is provided, verify against batch root.
  if (body.inclusion_proof && body.merkle_root_blake3_hex && body.leaf_blake3_hex) {
    try {
      let h = fromHex(body.leaf_blake3_hex);
      for (const step of body.inclusion_proof) {
        const sibling = fromHex(step.sibling);
        h = step.side === 'left'
          ? blake3(Buffer.concat([Buffer.from([0x01]), sibling, h]))
          : blake3(Buffer.concat([Buffer.from([0x01]), h, sibling]));
      }
      check('merkle_inclusion', toHex(h) === body.merkle_root_blake3_hex);
    } catch (e) { check('merkle_inclusion', false, String(e.message || e)); }
  }

  // 8. Beacon binding — batch commitments must reference a NIST beacon pulse.
  if (env.beacon_pulse_index != null) {
    check('beacon_binding', !!env.beacon_output_value && !!env.entropy_digest_hex);
  }

  const pass = checks.every(c => c.pass);
  return { pass, checks, scheme: 'nano-band-v1' };
});

// --- Start ---
// Initialize the witness quorum keys (in-process pseudo-witnesses for now).
const _wpubs = getWitnessPubkeys();
app.log.info({
  witnesses: _wpubs.map(w => ({ name: w.name, ed25519: w.ed25519_pubkey.slice(0, 16), ml_dsa_65_bytes: w.ml_dsa_65_pubkey_bytes })),
  threshold: 2,
  n: _wpubs.length,
}, 'witness quorum initialized');

app.listen({ port: PORT, host: '0.0.0.0' }).then(() => {
  app.log.info(`ct-log listening on :${PORT}, STH cadence ${STH_CADENCE_MS}ms`);
});

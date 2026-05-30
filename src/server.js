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
  signSTHDual, signSTHDualPQ,
} from './keys.js';
import { tryParseReceipt } from './receipt.js';
import {
  deriveHybridAgent,
  hybridSign,
  hybridVerify,
  deriveDidFromPubkeys,
  HYBRID_AGENT_SCHEME,
} from './hybrid-agent.js';
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
    bundle_version: 2,
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
      notice: 'The cryptographic transparency log architecture, the dual ed25519 + ML-DSA-65 STH co-signature, the dual-hash (BLAKE3 + SHA3-256) hash-agile Merkle commitment, the BLAKE3 leaf/internal domain-separated commitment scheme, the receipt-envelope canonical encoding, the multi-axis physical-entropy lattice handshake, and the self-verifying offline proof-bundle format are original work by Steve Rotzin. Patent Pending. Filed 2026-05-08.',
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

// --- Start ---
app.listen({ port: PORT, host: '0.0.0.0' }).then(() => {
  app.log.info(`ct-log listening on :${PORT}, STH cadence ${STH_CADENCE_MS}ms`);
});

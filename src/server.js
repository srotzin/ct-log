// Hive CT log + vestigium service.
// Endpoints:
//   GET  /v1/sth
//   POST /v1/submit
//   GET  /v1/proof/:leaf_hash
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
} from './merkle.js';
import { operatorPublicKey, signSTH } from './keys.js';
import { tryParseReceipt } from './receipt.js';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { blake3 } from '@noble/hashes/blake3';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const PORT = parseInt(process.env.PORT || '8080', 10);
const STH_CADENCE_MS = parseInt(process.env.STH_CADENCE_MS || '30000', 10);

const app = Fastify({ logger: { level: 'info' } });
await app.register(cors, { origin: true });

// --- Leaf cache: keep all leaf hashes in memory for proof generation. ---
let leafCache = [];
function rebuildLeafCache() {
  const rows = stmts.getAllLeafHashes.all();
  leafCache = rows.map(r => new Uint8Array(r.leaf_hash));
  app.log.info({ size: leafCache.length }, 'leaf cache rebuilt');
}
rebuildLeafCache();

// --- STH publication loop ---
async function publishSTH() {
  try {
    const size = leafCache.length;
    const root = merkleRoot(leafCache);
    const ts = Date.now();
    const latest = stmts.latestTreeHead.get();
    const epoch = latest ? latest.epoch + 1 : 1;
    const sig = signSTH({ epoch, treeSize: size, root, ts });
    stmts.insertTreeHead.run(size, Buffer.from(root), ts, Buffer.from(sig));
    app.log.info({ epoch, tree_size: size, root_prefix: toHex(root).slice(0, 16) }, 'STH published');
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
  };
});

app.get('/v1/sth', async (req, reply) => {
  const row = stmts.latestTreeHead.get();
  if (!row) return reply.code(503).send({ error: 'no STH yet' });
  return {
    epoch: row.epoch,
    tree_size: row.tree_size,
    root: toHex(row.root),
    ts: row.ts,
    sig: toHex(row.sig),
    operator_pubkey: operatorPublicKey ? toHex(operatorPublicKey) : null,
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
// Usage: GET /v1/attest/prefill?counterparty=circle  (or visa, aave, openai, etc.)
app.get('/v1/attest/prefill', async (req, reply) => {
  const counterparty = String(req.query.counterparty || 'test').toLowerCase().replace(/[^a-z0-9-]/g, '');
  if (!counterparty || counterparty.length > 32) {
    return reply.code(400).send({ error: 'bad counterparty name' });
  }

  const TREASURY_DID = 'did:hive:treasury-001';
  const counterparty_did = `did:${counterparty}:test`;

  // Anchor to current STH.
  const sth = stmts.latestTreeHead.get();
  if (!sth) return reply.code(503).send({ error: 'no STH yet' });

  // Treasury's current head.
  const treasuryHead = stmts.latestVestigium.get(TREASURY_DID);
  const prev_receipt_hash = treasuryHead ? toHex(treasuryHead.leaf_hash) : '0'.repeat(64);

  const ts = Date.now();
  const input_commit = toHex(blake3(`hive-${counterparty}-attestation-${ts}`));
  const output_commit = toHex(blake3('counterparty-attestation-acknowledged'));

  const canonical = {
    v: 1,
    agent_did: TREASURY_DID,
    prev_receipt_hash,
    log_sth_root: toHex(sth.root),
    log_sth_size: sth.tree_size,
    action_type: 'settlement',
    input_commit,
    output_commit,
    counterparty_did,
    ts,
  };
  const canonicalBytes = Buffer.from(JSON.stringify(canonical));
  return {
    counterparty_did,
    canonical_json: canonical,
    canonical_bytes_b64: canonicalBytes.toString('base64'),
    canonical_bytes_utf8: canonicalBytes.toString('utf8'),
    blake3_hex: toHex(blake3(canonicalBytes)),
    sth: { epoch: sth.epoch, tree_size: sth.tree_size, root: toHex(sth.root), ts: sth.ts },
    instructions: 'Sign canonical_bytes_b64 (decoded to raw bytes) with any Ed25519 key. POST {prefill_id, counterparty_pubkey_hex, counterparty_sig_hex, canonical_json} to /v1/attest/submit. Or use the one-line script at /sign.',
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

  const fullReceipt = {
    ...canonical_json,
    counterparty_sig: counterparty_sig_hex,
    counterparty_pubkey: counterparty_pubkey_hex,
    agent_sig: agent_sig_hex,
    agent_pubkey: agent_pubkey_hex,
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

  const current = stmts.vestigiumDepth.get(canonical_json.agent_did)?.depth || 0;
  const newDepth = current + 1;
  stmts.insertVestigium.run(canonical_json.agent_did, newDepth, seq, leafBuf, prevHashBuf, ts);

  const sth = stmts.latestTreeHead.get();
  return {
    ok: true,
    seq,
    leaf_hash: toHex(leaf),
    counterparty_did: canonical_json.counterparty_did,
    treasury_vestigium_depth: newDepth,
    sth: sth ? { epoch: sth.epoch, tree_size: sth.tree_size, root: toHex(sth.root), ts: sth.ts, sig: toHex(sth.sig) } : null,
    next_sth_in_ms: STH_CADENCE_MS,
    receipt_url: `/v1/proof/${toHex(leaf)}`,
  };
});

// --- Start ---
app.listen({ port: PORT, host: '0.0.0.0' }).then(() => {
  app.log.info(`ct-log listening on :${PORT}, STH cadence ${STH_CADENCE_MS}ms`);
});

// Verify ML-DSA-65 on the canonical 5 lattice receipts from a deployed log.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const base = process.argv[2] || 'https://ct-log.onrender.com';

const TARGETS = [
  { name: 'wave',       seq: 12 },
  { name: 'loess',      seq: 13 },
  { name: 'aurora',     seq: 14 },
  { name: 'rogue-wave', seq: 15 },
  { name: 'keystone',   seq: 16 },
];

const SIG_FIELDS = ['agent_sig','agent_pubkey','witness_sig','witness_pubkey','operator_pq_sig','operator_pq_pubkey','pq_scheme'];

function hex2bytes(h) { return Uint8Array.from(Buffer.from(h, 'hex')); }

let allPass = true;
for (const t of TARGETS) {
  const r = await fetch(`${base}/v1/entries?start=${t.seq}&end=${t.seq}`);
  const j = await r.json();
  const row = j.entries?.[0];
  if (!row) { console.log(`${t.name}: NO ENTRY at seq ${t.seq}`); allPass = false; continue; }
  const payload = Buffer.from(row.payload_b64, 'base64').toString('utf8');
  const receipt = JSON.parse(payload);

  // sanity: must be a lattice handshake
  const want_did = `did:lattice:${t.name}`;
  if (receipt.agent_did !== want_did) {
    console.log(`${t.name}: WRONG DID at seq ${t.seq} (got ${receipt.agent_did})`);
    allPass = false; continue;
  }

  // strip sig fields preserving order
  const canonical = {};
  for (const k of Object.keys(receipt)) {
    if (!SIG_FIELDS.includes(k)) canonical[k] = receipt[k];
  }
  const msg = Buffer.from(JSON.stringify(canonical));
  const pq_sig = hex2bytes(receipt.operator_pq_sig);
  const pq_pub = hex2bytes(receipt.operator_pq_pubkey);
  const ok = ml_dsa65.verify(pq_sig, msg, pq_pub);
  if (!ok) allPass = false;
  console.log(`${t.name.padEnd(11)} seq=${t.seq}  leaf=${row.leaf_hash.slice(0,16)}  digest=${receipt.lattice.entropy_digest.slice(0,16)}  records=${receipt.lattice.record_count}  ML-DSA-65=${ok ? 'PASS' : 'FAIL'}`);
}

console.log('---');
console.log(allPass ? 'ALL 5 PASS' : 'SOME FAILED');
process.exit(allPass ? 0 : 1);

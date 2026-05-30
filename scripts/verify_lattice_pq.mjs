// Verify ML-DSA-65 on a lattice receipt envelope.
// Usage: node scripts/verify_lattice_pq.mjs <base_url> <lattice_name>
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const base = process.argv[2] || 'http://localhost:3789';
const name = process.argv[3] || 'wave';

function hex2bytes(h) { return Uint8Array.from(Buffer.from(h, 'hex')); }

const r = await fetch(`${base}/v1/lattice/${name}/handshake`, { method: 'POST' });
const j = await r.json();
if (!j.ok && !j.duplicate) { console.error('handshake failed', j); process.exit(1); }

const seq = j.seq;
const leaf = j.leaf_hash;

// Fetch the raw payload from /v1/entries
const ent = await fetch(`${base}/v1/entries?start=${seq}&end=${seq}`).then(x => x.json());
const row = ent.entries[0];
if (!row) { console.error('entry not found', ent); process.exit(1); }
const payload = Buffer.from(row.payload_b64, 'base64').toString('utf8');
const receipt = JSON.parse(payload);

// Strip signature fields, preserving insertion order.
const SIG_FIELDS = ['agent_sig','agent_pubkey','witness_sig','witness_pubkey','operator_pq_sig','operator_pq_pubkey','pq_scheme'];
const canonical = {};
for (const k of Object.keys(receipt)) {
  if (!SIG_FIELDS.includes(k)) canonical[k] = receipt[k];
}

console.log(`lattice: ${name}`);
console.log(`seq:     ${seq}`);
console.log(`leaf:    ${leaf}`);
console.log(`source:  ${canonical.lattice?.source_url}`);
console.log(`digest:  ${canonical.lattice?.entropy_digest}`);
console.log(`records: ${canonical.lattice?.record_count}`);

const msg = Buffer.from(JSON.stringify(canonical));
const pq_sig = hex2bytes(receipt.operator_pq_sig);
const pq_pub = hex2bytes(receipt.operator_pq_pubkey);
const ok = ml_dsa65.verify(pq_sig, msg, pq_pub);
console.log(`scheme:  ${receipt.pq_scheme}`);
console.log(`ML-DSA-65 envelope verify: ${ok ? 'PASS' : 'FAIL'}`);
process.exit(ok ? 0 : 1);

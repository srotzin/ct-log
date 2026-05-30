import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

async function get(url) {
  const r = await fetch(url);
  return r.json();
}

const entries = await get('https://ct-log.onrender.com/v1/entries?start=11&end=11');
const pkResp = await get('https://ct-log.onrender.com/.well-known/ct-pq-pubkey');
const pkBytes = Buffer.from(pkResp.pubkey_hex, 'hex');

for (const e of entries.entries) {
  const p = JSON.parse(Buffer.from(e.payload_b64, 'base64').toString());
  console.log('=== seq', e.seq, '===');
  console.log('agent_did:', p.agent_did);
  console.log('action_type:', p.action_type);
  console.log('pq_scheme:', p.pq_scheme);
  console.log('operator_pq_pubkey (first 60):', (p.operator_pq_pubkey || 'NONE').slice(0, 60));
  console.log('operator_pq_sig len:', (p.operator_pq_sig || '').length / 2, 'bytes');
  console.log('agent_pubkey (counterparty):', p.agent_pubkey);
  console.log('witness_did:', p.witness_did);
  console.log('witness_pubkey (treasury):', p.witness_pubkey);

  if (p.operator_pq_sig) {
    // Reconstruct canonical envelope (the bytes the operator PQ-signed)
    const canon = {
      v: p.v, agent_did: p.agent_did, prev_receipt_hash: p.prev_receipt_hash,
      log_sth_root: p.log_sth_root, log_sth_size: p.log_sth_size,
      action_type: p.action_type, input_commit: p.input_commit,
      output_commit: p.output_commit, witness_did: p.witness_did, ts: p.ts,
    };
    const canonBytes = Buffer.from(JSON.stringify(canon));
    const sig = Buffer.from(p.operator_pq_sig, 'hex');
    const ok = ml_dsa65.verify(sig, canonBytes, pkBytes);
    console.log('ML-DSA-65 VERIFY:', ok ? 'PASS' : 'FAIL');
  }
}

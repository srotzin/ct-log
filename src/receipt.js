// POEP receipt envelope.
// Canonical JSON encoding for signing: sorted keys, no whitespace.

import { blake3 } from '@noble/hashes/blake3';

export const RECEIPT_KINDS = new Set([
  'heartbeat',
  'settlement',
  'credential_issue',
  'cert_issue',
  'route_decision',
  'route_refusal',
  'sth_publish',
  'generic',
]);

// Fields that participate in the agent signature, in canonical order.
const SIGNED_FIELDS = [
  'v',
  'agent_did',
  'prev_receipt_hash',
  'log_sth_root',
  'log_sth_size',
  'action_type',
  'input_commit',
  'output_commit',
  'counterparty_did',
  'counterparty_sig',
  'ts',
];

export function canonicalBytes(receipt) {
  const obj = {};
  for (const k of SIGNED_FIELDS) obj[k] = receipt[k] ?? null;
  return Buffer.from(JSON.stringify(obj));
}

export function receiptLeafHash(receipt) {
  // The leaf hash covers EVERYTHING including the agent signature.
  // So we sign the canonical signed-fields blob, then hash the full envelope including the sig.
  const full = { ...receipt };
  const fullBytes = Buffer.from(JSON.stringify(full, Object.keys(full).sort()));
  return blake3(fullBytes);
}

export function validateReceiptShape(r) {
  if (!r || typeof r !== 'object') return 'not_an_object';
  if (r.v !== 1) return 'bad_version';
  if (typeof r.agent_did !== 'string' || !r.agent_did.startsWith('did:')) return 'bad_agent_did';
  if (typeof r.prev_receipt_hash !== 'string') return 'bad_prev_hash';
  if (typeof r.log_sth_root !== 'string') return 'bad_sth_root';
  if (typeof r.log_sth_size !== 'number') return 'bad_sth_size';
  if (typeof r.action_type !== 'string') return 'bad_action_type';
  if (!RECEIPT_KINDS.has(r.action_type)) return 'unknown_action_type';
  if (typeof r.ts !== 'number') return 'bad_ts';
  if (typeof r.agent_sig !== 'string') return 'bad_agent_sig';
  return null;
}

export function tryParseReceipt(payload) {
  try {
    const r = JSON.parse(Buffer.from(payload).toString('utf8'));
    const err = validateReceiptShape(r);
    if (err) return { ok: false, err };
    return { ok: true, receipt: r };
  } catch (e) {
    return { ok: false, err: 'parse_error' };
  }
}

// Log operator Ed25519 key management.

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const PRIV_HEX = process.env.LOG_OPERATOR_PRIVATE_KEY;
if (!PRIV_HEX) {
  console.warn('[keys] LOG_OPERATOR_PRIVATE_KEY not set. Generate one with: node src/init-key.js');
}

export const operatorPrivateKey = PRIV_HEX ? new Uint8Array(Buffer.from(PRIV_HEX, 'hex')) : null;
export const operatorPublicKey = operatorPrivateKey ? ed.getPublicKey(operatorPrivateKey) : null;

export function signSTH({ epoch, treeSize, root, ts }) {
  if (!operatorPrivateKey) throw new Error('operator key not configured');
  // Canonical encoding: epoch(8) || treeSize(8) || root(32) || ts(8), big-endian.
  const buf = Buffer.alloc(8 + 8 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(treeSize), 8);
  Buffer.from(root).copy(buf, 16);
  buf.writeBigUInt64BE(BigInt(ts), 48);
  return ed.sign(buf, operatorPrivateKey);
}

export function verifySTH({ epoch, treeSize, root, ts, sig }, pubkey) {
  const buf = Buffer.alloc(8 + 8 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(treeSize), 8);
  Buffer.from(root).copy(buf, 16);
  buf.writeBigUInt64BE(BigInt(ts), 48);
  return ed.verify(sig, buf, pubkey);
}

// Verify an agent's signature on a receipt envelope's canonical bytes.
export function verifyAgentSig(canonicalBytes, sig, agentPubkey) {
  return ed.verify(sig, canonicalBytes, agentPubkey);
}

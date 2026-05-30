// Log operator key management: classical Ed25519 + post-quantum ML-DSA-65 (FIPS 204).

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const PRIV_HEX = process.env.LOG_OPERATOR_PRIVATE_KEY;
if (!PRIV_HEX) {
  console.warn('[keys] LOG_OPERATOR_PRIVATE_KEY not set. Generate one with: node src/init-key.js');
}

export const operatorPrivateKey = PRIV_HEX ? new Uint8Array(Buffer.from(PRIV_HEX, 'hex')) : null;
export const operatorPublicKey = operatorPrivateKey ? ed.getPublicKey(operatorPrivateKey) : null;

// Post-quantum operator key (ML-DSA-65 / FIPS 204). Derived deterministically from a 32-byte seed.
const PQ_SEED_HEX = process.env.LOG_OPERATOR_PQ_SEED;
let _pqKp = null;
if (PQ_SEED_HEX) {
  const seed = new Uint8Array(Buffer.from(PQ_SEED_HEX, 'hex'));
  if (seed.length !== 32) {
    console.warn('[keys] LOG_OPERATOR_PQ_SEED must be 32 bytes hex (64 chars), got ' + seed.length);
  } else {
    _pqKp = ml_dsa65.keygen(seed);
    console.log('[keys] ML-DSA-65 operator key loaded. pubkey bytes=' + _pqKp.publicKey.length);
  }
} else {
  console.warn('[keys] LOG_OPERATOR_PQ_SEED not set. PQ co-signature disabled.');
}
export const operatorPqPublicKey = _pqKp ? _pqKp.publicKey : null;
export const operatorPqScheme = _pqKp ? 'ML-DSA-65' : null;

export function signSTHPQ({ epoch, treeSize, root, ts }) {
  if (!_pqKp) return null;
  const buf = Buffer.alloc(8 + 8 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(treeSize), 8);
  Buffer.from(root).copy(buf, 16);
  buf.writeBigUInt64BE(BigInt(ts), 48);
  return ml_dsa65.sign(buf, _pqKp.secretKey);
}

export function verifySTHPQ({ epoch, treeSize, root, ts, pqSig }, pqPubkey) {
  const buf = Buffer.alloc(8 + 8 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(treeSize), 8);
  Buffer.from(root).copy(buf, 16);
  buf.writeBigUInt64BE(BigInt(ts), 48);
  return ml_dsa65.verify(pqSig, buf, pqPubkey);
}

// Sign arbitrary canonical bytes with PQ operator key (for receipt envelope PQ co-sig).
export function signBytesPQ(canonicalBytes) {
  if (!_pqKp) return null;
  return ml_dsa65.sign(canonicalBytes, _pqKp.secretKey);
}

// ---- Hash-agility (Vector 1): dual-root STH ----
// Extended canonical encoding includes BOTH Merkle roots:
//   epoch(8) || tree_size(8) || root_blake3(32) || root_sha3(32) || ts(8)  big-endian
// This is signed in parallel to the legacy single-root STH so any party
// can verify either commitment independently.

export function encodeSTHDual({ epoch, treeSize, rootBlake3, rootSha3, ts }) {
  const buf = Buffer.alloc(8 + 8 + 32 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(treeSize), 8);
  Buffer.from(rootBlake3).copy(buf, 16);
  Buffer.from(rootSha3).copy(buf, 48);
  buf.writeBigUInt64BE(BigInt(ts), 80);
  return buf;
}

export function signSTHDual({ epoch, treeSize, rootBlake3, rootSha3, ts }) {
  if (!operatorPrivateKey) throw new Error('operator ed25519 key not configured');
  return ed.sign(encodeSTHDual({ epoch, treeSize, rootBlake3, rootSha3, ts }), operatorPrivateKey);
}

export function signSTHDualPQ({ epoch, treeSize, rootBlake3, rootSha3, ts }) {
  if (!_pqKp) return null;
  return ml_dsa65.sign(encodeSTHDual({ epoch, treeSize, rootBlake3, rootSha3, ts }), _pqKp.secretKey);
}

export function verifySTHDual({ epoch, treeSize, rootBlake3, rootSha3, ts, sig }, pubkey) {
  return ed.verify(sig, encodeSTHDual({ epoch, treeSize, rootBlake3, rootSha3, ts }), pubkey);
}

export function verifySTHDualPQ({ epoch, treeSize, rootBlake3, rootSha3, ts, pqSig }, pqPubkey) {
  return ml_dsa65.verify(pqSig, encodeSTHDual({ epoch, treeSize, rootBlake3, rootSha3, ts }), pqPubkey);
}

export function signSTH({ epoch, treeSize, root, ts }) {
  if (!operatorPrivateKey) throw new Error('operator ed25519 key not configured');
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

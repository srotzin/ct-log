// RFC 6962-style Merkle tree over BLAKE3.
// Domain separation: leaf prefix 0x00, internal prefix 0x01.
// Used for the global CT log and the per-agent vestigium accumulator.

import { blake3 } from '@noble/hashes/blake3';

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

export function hashLeaf(payload) {
  // payload: Uint8Array
  return blake3(concat(LEAF_PREFIX, payload));
}

export function hashNode(left, right) {
  return blake3(concat(NODE_PREFIX, left, right));
}

// Compute the Merkle root of an array of leaf hashes (already prefixed/hashed).
// RFC 6962 deterministic structure with right-leaning incomplete nodes promoted.
export function merkleRoot(leaves) {
  if (leaves.length === 0) {
    // Empty tree root convention: BLAKE3 of empty string.
    return blake3(new Uint8Array(0));
  }
  if (leaves.length === 1) return leaves[0];
  // Find largest power of 2 < n
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  const left = merkleRoot(leaves.slice(0, k));
  const right = merkleRoot(leaves.slice(k));
  return hashNode(left, right);
}

// Inclusion proof for leaf at index m in tree of size n.
// Returns array of sibling hashes (bottom-up).
export function inclusionProof(leaves, m) {
  const n = leaves.length;
  if (m < 0 || m >= n) throw new Error('index out of range');
  const proof = [];
  function recurse(lo, hi, idx) {
    if (hi - lo === 1) return;
    let k = 1;
    while (k * 2 < hi - lo) k *= 2;
    if (idx < lo + k) {
      proof.push(merkleRoot(leaves.slice(lo + k, hi)));
      recurse(lo, lo + k, idx);
    } else {
      proof.push(merkleRoot(leaves.slice(lo, lo + k)));
      recurse(lo + k, hi, idx);
    }
  }
  recurse(0, n, m);
  return proof;
}

// Verify an inclusion proof.
export function verifyInclusion(leafHash, index, treeSize, proof, root) {
  let h = leafHash;
  let m = index;
  let n = treeSize;
  let i = 0;
  while (n > 1) {
    let k = 1;
    while (k * 2 < n) k *= 2;
    if (m < k) {
      const sib = proof[proof.length - 1 - i];
      h = hashNode(h, sib);
      n = k;
    } else {
      const sib = proof[proof.length - 1 - i];
      h = hashNode(sib, h);
      m = m - k;
      n = n - k;
    }
    i++;
  }
  return Buffer.compare(Buffer.from(h), Buffer.from(root)) === 0;
}

// Consistency proof between trees of size m and n (m <= n).
export function consistencyProof(leaves, m, n) {
  if (m === 0 || m === n) return [];
  const proof = [];
  function recurse(lo, hi, sn, sameRoot) {
    if (sn === hi - lo) {
      if (!sameRoot) proof.push(merkleRoot(leaves.slice(lo, hi)));
      return;
    }
    let k = 1;
    while (k * 2 < hi - lo) k *= 2;
    if (sn <= k) {
      recurse(lo, lo + k, sn, sameRoot);
      proof.push(merkleRoot(leaves.slice(lo + k, hi)));
    } else {
      recurse(lo + k, hi, sn - k, false);
      proof.push(merkleRoot(leaves.slice(lo, lo + k)));
    }
  }
  recurse(0, leaves.length, m, true);
  return proof;
}

export function toHex(u8) {
  return Buffer.from(u8).toString('hex');
}
export function fromHex(s) {
  return new Uint8Array(Buffer.from(s, 'hex'));
}

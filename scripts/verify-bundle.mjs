#!/usr/bin/env node
// verify-bundle.mjs -- offline verifier for a Hive CT log proof-bundle.
//
// Usage:
//   node verify-bundle.mjs path/to/bundle.json
//
// Verifies, with NO network access:
//   1. leaf_hash == BLAKE3(0x00 || receipt_envelope_bytes)
//   2. Merkle inclusion against STH root (RFC 6962 structure, BLAKE3 0x00/0x01 prefix)
//   3. STH ed25519 signature over canonical encoding
//      epoch(8) || tree_size(8) || root(32) || ts(8), big-endian
//   4. STH ML-DSA-65 signature over the same canonical encoding (FIPS 204)
//
// Exit code 0 if ALL checks PASS; 1 otherwise.
//
// Dependencies (already in ct-log/package.json):
//   @noble/hashes  @noble/ed25519  @noble/post-quantum

import { readFileSync } from 'node:fs';
import { blake3 } from '@noble/hashes/blake3';
import { sha512 } from '@noble/hashes/sha512';
import * as ed from '@noble/ed25519';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

function fromHex(h) { return new Uint8Array(Buffer.from(h, 'hex')); }
function toHex(u8)  { return Buffer.from(u8).toString('hex'); }
function concat(...arrs) {
  let n = 0; for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

function hashLeaf(payload) { return blake3(concat(LEAF_PREFIX, payload)); }
function hashNode(l, r)    { return blake3(concat(NODE_PREFIX, l, r)); }

// RFC 6962-style inclusion verify (matches ct-log/src/merkle.js).
function verifyInclusion(leafHash, index, treeSize, proofHexes, rootHex) {
  let h = leafHash;
  let m = index;
  let n = treeSize;
  const proof = proofHexes.map(fromHex);
  let i = 0;
  while (n > 1) {
    let k = 1;
    while (k * 2 < n) k *= 2;
    const sib = proof[proof.length - 1 - i];
    if (m < k) {
      h = hashNode(h, sib);
      n = k;
    } else {
      h = hashNode(sib, h);
      m = m - k;
      n = n - k;
    }
    i++;
  }
  return toHex(h) === rootHex;
}

function encodeSTH({ epoch, tree_size, root, ts }) {
  const buf = Buffer.alloc(8 + 8 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(tree_size), 8);
  Buffer.from(root, 'hex').copy(buf, 16);
  buf.writeBigUInt64BE(BigInt(ts), 48);
  return new Uint8Array(buf);
}

function fmt(label, ok, extra = '') {
  const tag = ok ? 'PASS' : 'FAIL';
  return `  [${tag}]  ${label}${extra ? '  ' + extra : ''}`;
}

async function main() {
  const path = process.argv[2];
  if (!path) {
    console.error('usage: node verify-bundle.mjs <bundle.json>');
    process.exit(2);
  }
  const bundle = JSON.parse(readFileSync(path, 'utf8'));
  console.log(`Hive CT proof-bundle  ::  ${path}`);
  console.log(`  log_name=${bundle.log_name}  seq=${bundle.seq}  leaf=${bundle.leaf_hash.slice(0, 16)}...`);
  console.log(`  epoch=${bundle.sth.epoch}  tree_size=${bundle.sth.tree_size}  root=${bundle.sth.root.slice(0, 16)}...`);
  console.log('');

  const checks = [];

  // 1. Leaf hash matches BLAKE3(0x00 || payload)
  const payload = Buffer.from(bundle.receipt_envelope_b64, 'base64');
  const computedLeaf = toHex(hashLeaf(payload));
  const leafOk = computedLeaf === bundle.leaf_hash;
  checks.push(['leaf_hash = BLAKE3(0x00 || envelope_bytes)', leafOk,
    leafOk ? `(${payload.length} envelope bytes)` : `(got ${computedLeaf.slice(0,16)}...)`]);

  // 2. Merkle inclusion against STH root
  const incOk = verifyInclusion(
    fromHex(bundle.leaf_hash),
    bundle.index,
    bundle.sth.tree_size,
    bundle.merkle.proof,
    bundle.sth.root,
  );
  checks.push([`Merkle inclusion @ index ${bundle.index} / tree_size ${bundle.sth.tree_size}`, incOk,
    `(${bundle.merkle.proof.length} sibling hashes)`]);

  // 3. STH ed25519 signature
  const sthBytes = encodeSTH(bundle.sth);
  let edOk = false;
  try {
    edOk = bundle.operator.ed25519_pubkey
      ? ed.verify(fromHex(bundle.sth.ed25519_sig), sthBytes, fromHex(bundle.operator.ed25519_pubkey))
      : false;
  } catch (_) { edOk = false; }
  checks.push(['STH ed25519 sig (classical)', edOk,
    bundle.operator.ed25519_pubkey ? `(pubkey ${bundle.operator.ed25519_pubkey.slice(0,16)}...)` : '(no pubkey)']);

  // 4. STH ML-DSA-65 signature
  let pqOk = false, pqInfo = '(absent)';
  if (bundle.sth.pq_sig && bundle.operator.pq_pubkey) {
    try {
      pqOk = ml_dsa65.verify(fromHex(bundle.sth.pq_sig), sthBytes, fromHex(bundle.operator.pq_pubkey));
      pqInfo = `(${bundle.sth.pq_scheme}, pubkey bytes=${fromHex(bundle.operator.pq_pubkey).length}, sig bytes=${fromHex(bundle.sth.pq_sig).length})`;
    } catch (e) { pqOk = false; pqInfo = `(verify error: ${e.message})`; }
  }
  checks.push([`STH ${bundle.sth.pq_scheme || 'ML-DSA-65'} sig (post-quantum, FIPS 204)`, pqOk, pqInfo]);

  for (const [label, ok, extra] of checks) console.log(fmt(label, ok, extra));
  console.log('');

  const allOk = checks.every(([, ok]) => ok);
  if (allOk) {
    console.log('  ALL CHECKS PASS  ::  bundle is cryptographically valid offline.');
    process.exit(0);
  } else {
    console.log('  FAILED  ::  one or more checks did not verify.');
    process.exit(1);
  }
}

main().catch(e => { console.error('verifier crashed:', e); process.exit(2); });

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
import { sha3_256 } from '@noble/hashes/sha3';
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
function hashLeafSha3(payload) { return sha3_256(concat(LEAF_PREFIX, payload)); }
function hashNodeSha3(l, r)    { return sha3_256(concat(NODE_PREFIX, l, r)); }

// Inclusion verify — mirrors the recursive proof construction in ct-log/src/merkle.js.
// Proof is pushed outer-split-first (root-side) during construction, so we recurse
// the same way and consume proof[depth] at each level. nodeHash is parameterised
// so the same routine works for BLAKE3 or SHA3-256.
function verifyInclusionWith(nodeHash, leafHash, index, treeSize, proofHexes, rootHex) {
  const proof = proofHexes.map(fromHex);
  function recurse(lo, hi, idx, depth) {
    if (hi - lo === 1) return leafHash;
    let k = 1;
    while (k * 2 < hi - lo) k *= 2;
    const sib = proof[depth];
    if (idx < lo + k) {
      const left = recurse(lo, lo + k, idx, depth + 1);
      return nodeHash(left, sib);
    } else {
      const right = recurse(lo + k, hi, idx, depth + 1);
      return nodeHash(sib, right);
    }
  }
  const computed = recurse(0, treeSize, index, 0);
  return toHex(computed) === rootHex;
}
function verifyInclusion(leafHash, index, treeSize, proofHexes, rootHex) {
  return verifyInclusionWith(hashNode, leafHash, index, treeSize, proofHexes, rootHex);
}
function verifyInclusionSha3(leafHash, index, treeSize, proofHexes, rootHex) {
  return verifyInclusionWith(hashNodeSha3, leafHash, index, treeSize, proofHexes, rootHex);
}

function encodeSTH({ epoch, tree_size, root, ts }) {
  const buf = Buffer.alloc(8 + 8 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(tree_size), 8);
  Buffer.from(root, 'hex').copy(buf, 16);
  buf.writeBigUInt64BE(BigInt(ts), 48);
  return new Uint8Array(buf);
}

function encodeSTHDual({ epoch, tree_size, root_blake3, root_sha3_256, ts }) {
  const buf = Buffer.alloc(8 + 8 + 32 + 32 + 8);
  buf.writeBigUInt64BE(BigInt(epoch), 0);
  buf.writeBigUInt64BE(BigInt(tree_size), 8);
  Buffer.from(root_blake3, 'hex').copy(buf, 16);
  Buffer.from(root_sha3_256, 'hex').copy(buf, 48);
  buf.writeBigUInt64BE(BigInt(ts), 80);
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

  // ---- Hash agility (Vector 1): independent SHA3-256 verification path ----
  if (bundle.merkle_sha3 && bundle.sth_dual) {
    // 5. SHA3-256 leaf hash matches
    const computedSha3Leaf = toHex(hashLeafSha3(payload));
    const sha3LeafOk = computedSha3Leaf === bundle.merkle_sha3.leaf_hash;
    checks.push(['SHA3-256 leaf = SHA3-256(0x00 || envelope_bytes)', sha3LeafOk,
      sha3LeafOk ? '(NIST-aligned hash)' : `(got ${computedSha3Leaf.slice(0,16)}...)`]);

    // 6. SHA3-256 Merkle inclusion against root_sha3_256
    const sha3IncOk = verifyInclusionSha3(
      fromHex(bundle.merkle_sha3.leaf_hash),
      bundle.index,
      bundle.merkle_sha3.tree_size,
      bundle.merkle_sha3.proof,
      bundle.sth_dual.root_sha3_256,
    );
    checks.push([`SHA3-256 Merkle inclusion @ index ${bundle.index} / tree_size ${bundle.merkle_sha3.tree_size}`, sha3IncOk,
      `(${bundle.merkle_sha3.proof.length} sibling hashes)`]);

    // 7. Dual-root ed25519 STH signature (commits to BOTH roots)
    const sthDualBytes = encodeSTHDual({
      epoch: bundle.sth.epoch,
      tree_size: bundle.sth.tree_size,
      root_blake3: bundle.sth_dual.root_blake3,
      root_sha3_256: bundle.sth_dual.root_sha3_256,
      ts: bundle.sth.ts,
    });
    let dualEdOk = false;
    try {
      dualEdOk = bundle.sth_dual.ed25519_sig && bundle.operator.ed25519_pubkey
        ? ed.verify(fromHex(bundle.sth_dual.ed25519_sig), sthDualBytes, fromHex(bundle.operator.ed25519_pubkey))
        : false;
    } catch (_) { dualEdOk = false; }
    checks.push(['Dual-root STH ed25519 sig (commits BLAKE3 + SHA3-256)', dualEdOk, '(hash agility)']);

    // 8. Dual-root ML-DSA-65 STH signature
    let dualPqOk = false, dualPqInfo = '(absent)';
    if (bundle.sth_dual.pq_sig && bundle.operator.pq_pubkey) {
      try {
        dualPqOk = ml_dsa65.verify(fromHex(bundle.sth_dual.pq_sig), sthDualBytes, fromHex(bundle.operator.pq_pubkey));
        dualPqInfo = `(${bundle.sth_dual.pq_scheme}, sig bytes=${fromHex(bundle.sth_dual.pq_sig).length})`;
      } catch (e) { dualPqOk = false; dualPqInfo = `(verify error: ${e.message})`; }
    }
    checks.push([`Dual-root STH ${bundle.sth_dual.pq_scheme || 'ML-DSA-65'} sig (post-quantum + hash-agile)`, dualPqOk, dualPqInfo]);
  }

  for (const [label, ok, extra] of checks) console.log(fmt(label, ok, extra));
  console.log('');

  const allOk = checks.every(([, ok]) => ok);
  if (allOk) {
    console.log('  ALL CHECKS PASS  ::  bundle is cryptographically valid offline.');
  } else {
    console.log('  FAILED  ::  one or more checks did not verify.');
  }

  if (bundle.ip) {
    console.log('');
    console.log(`  IP  ::  ${bundle.ip.patent_status} · Filed ${bundle.ip.patent_filed} · ${bundle.ip.inventor} / ${bundle.ip.assignee}`);
  }

  process.exit(allOk ? 0 : 1);
}

main().catch(e => { console.error('verifier crashed:', e); process.exit(2); });

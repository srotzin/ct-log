import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const sth = await (await fetch('https://ct-log.onrender.com/v1/sth')).json();
const pk = await (await fetch('https://ct-log.onrender.com/.well-known/ct-pq-pubkey')).json();

console.log('STH epoch:', sth.epoch, 'tree_size:', sth.tree_size);
console.log('root:', sth.root);
console.log('pq_scheme:', sth.pq_scheme);
console.log('pq_sig len:', sth.pq_sig.length/2, 'bytes');

// Canonical encoding: epoch(8) || tree_size(8) || root(32) || ts(8), big-endian
const buf = Buffer.alloc(56);
buf.writeBigUInt64BE(BigInt(sth.epoch), 0);
buf.writeBigUInt64BE(BigInt(sth.tree_size), 8);
Buffer.from(sth.root, 'hex').copy(buf, 16);
buf.writeBigUInt64BE(BigInt(sth.ts), 48);

const pkBytes = Buffer.from(pk.pubkey_hex, 'hex');
const sigBytes = Buffer.from(sth.pq_sig, 'hex');
const ok = ml_dsa65.verify(sigBytes, buf, pkBytes);
console.log('STH ML-DSA-65 VERIFY:', ok ? 'PASS' : 'FAIL');
console.log('tree contains receipt seq 11:', sth.tree_size >= 11 ? 'YES' : 'NO (still waiting)');

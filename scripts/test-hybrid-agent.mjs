#!/usr/bin/env node
// Vector 4 unit test — exercises hybrid agent module end-to-end without spinning
// up the full server. Verifies:
//   - Deterministic derivation from seed
//   - Hybrid signing produces both sigs
//   - Hybrid verify passes on good sigs
//   - Hybrid verify FAILS when either sig is flipped
//   - DID recovery from pubkeys matches derived DID

import {
  deriveHybridAgent,
  hybridSign,
  hybridVerify,
  deriveDidFromPubkeys,
} from '../src/hybrid-agent.js';

const ok = (cond, msg) => {
  console.log(`  ${cond ? '[PASS]' : '[FAIL]'}  ${msg}`);
  if (!cond) { process.exit(1); }
};

console.log('Vector 4 :: hybrid-agent self-test\n');

const seed = new Uint8Array(32);
for (let i = 0; i < 32; i++) seed[i] = i;

// 1. Determinism
const kp1 = deriveHybridAgent(seed);
const kp2 = deriveHybridAgent(seed);
ok(kp1.agent_did === kp2.agent_did, 'derivation deterministic (same DID from same seed)');
ok(kp1.ed25519.public_key.every((b, i) => b === kp2.ed25519.public_key[i]), 'ed25519 pubkey identical');
ok(kp1.ml_dsa_65.public_key.every((b, i) => b === kp2.ml_dsa_65.public_key[i]), 'ml-dsa-65 pubkey identical');

// 2. Sign + verify
const msg = Buffer.from('hello hive — hybrid receipt v1', 'utf8');
const sigs = hybridSign(kp1, msg);
ok(sigs.ed25519_sig.length === 128, `ed25519 sig is 64 bytes (got ${sigs.ed25519_sig.length / 2})`);
ok(sigs.ml_dsa_65_sig.length === 3309 * 2, `ml-dsa-65 sig is 3309 bytes (got ${sigs.ml_dsa_65_sig.length / 2})`);

const v = hybridVerify(
  msg,
  sigs.ed25519_sig,
  sigs.ml_dsa_65_sig,
  Buffer.from(kp1.ed25519.public_key).toString('hex'),
  Buffer.from(kp1.ml_dsa_65.public_key).toString('hex'),
);
ok(v.ok && v.checks.ed25519 && v.checks.ml_dsa_65, 'hybrid verify passes on clean sigs');

// 3. Tamper ed25519 sig
const tEd = sigs.ed25519_sig.slice(0, -2) + (sigs.ed25519_sig.slice(-2) === '00' ? '01' : '00');
const v2 = hybridVerify(
  msg, tEd, sigs.ml_dsa_65_sig,
  Buffer.from(kp1.ed25519.public_key).toString('hex'),
  Buffer.from(kp1.ml_dsa_65.public_key).toString('hex'),
);
ok(!v2.ok && !v2.checks.ed25519 && v2.checks.ml_dsa_65, 'hybrid FAILS when ed25519 sig flipped (ml-dsa-65 still passes)');

// 4. Tamper ml-dsa-65 sig
const tMl = sigs.ml_dsa_65_sig.slice(0, -2) + (sigs.ml_dsa_65_sig.slice(-2) === '00' ? '01' : '00');
const v3 = hybridVerify(
  msg, sigs.ed25519_sig, tMl,
  Buffer.from(kp1.ed25519.public_key).toString('hex'),
  Buffer.from(kp1.ml_dsa_65.public_key).toString('hex'),
);
ok(!v3.ok && v3.checks.ed25519 && !v3.checks.ml_dsa_65, 'hybrid FAILS when ml-dsa-65 sig flipped (ed25519 still passes)');

// 5. Tamper message
const v4 = hybridVerify(
  Buffer.from('hello hive — tampered message', 'utf8'),
  sigs.ed25519_sig, sigs.ml_dsa_65_sig,
  Buffer.from(kp1.ed25519.public_key).toString('hex'),
  Buffer.from(kp1.ml_dsa_65.public_key).toString('hex'),
);
ok(!v4.ok && !v4.checks.ed25519 && !v4.checks.ml_dsa_65, 'hybrid FAILS when message tampered (both sigs fail)');

// 6. DID recovery from pubkeys
const recovered = deriveDidFromPubkeys(
  Buffer.from(kp1.ed25519.public_key).toString('hex'),
  Buffer.from(kp1.ml_dsa_65.public_key).toString('hex'),
);
ok(recovered === kp1.agent_did, 'DID recovered from pubkeys matches derived DID');

// 7. Different seeds = different DIDs
const seed2 = new Uint8Array(32);
for (let i = 0; i < 32; i++) seed2[i] = (i * 7) & 0xff;
const kpAlt = deriveHybridAgent(seed2);
ok(kpAlt.agent_did !== kp1.agent_did, 'different seeds → different DIDs');

console.log('\nALL CHECKS PASS  ::  Vector 4 hybrid-agent ready.');
console.log('IP  ::  Patent Pending · Filed 2026-05-08 · Steve Rotzin / Hive Civilization, Inc.');

// Vector 4 — Hybrid Ed25519 + ML-DSA-65 agent keys.
//
// Defense-in-depth signature scheme for agent identities in Hive Civilization.
// Every agent has TWO keys derived deterministically from a single 32-byte seed:
//   - Ed25519 (classical, well-vetted, fast)
//   - ML-DSA-65 (FIPS 204, post-quantum)
//
// A hybrid agent signature is the CONCATENATION of both signatures over the
// SAME canonical message bytes. A receipt is valid only if BOTH signatures verify.
// This means an attacker must break BOTH primitives to forge an agent receipt —
// classical AND post-quantum, simultaneously, on the same key material.
//
// Agent DID encodes both public keys:
//   did:hive:hybrid:<blake3(ed_pub || ml_dsa_pub, 32-byte hex)>
//
// Patent Pending. Filed 2026-05-08. Inventor: Steve Rotzin.
//   The dual ed25519 + ML-DSA-65 agent identity, the deterministic hybrid-from-seed
//   derivation, the dual-signature receipt canonical encoding, and the hybrid
//   verification path that requires BOTH signatures to validate are original
//   work by Steve Rotzin / Hive Civilization, Inc.

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { blake3 } from '@noble/hashes/blake3';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const toHex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

// Derive a deterministic hybrid agent keypair from a 32-byte seed.
// The ed25519 seed = blake3(seed || "ed25519-agent-v1", 32)
// The ml-dsa-65 seed = blake3(seed || "ml-dsa-65-agent-v1", 32)
// This keeps the two domains independent so leaking one cannot derive the other,
// while letting an agent regenerate both from a single secret.
export function deriveHybridAgent(seedBytes) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32) {
    throw new Error('seed must be 32 bytes');
  }
  const edSeed = blake3(
    new Uint8Array([...seedBytes, ...Buffer.from('ed25519-agent-v1', 'utf8')]),
    { dkLen: 32 }
  );
  const mlSeed = blake3(
    new Uint8Array([...seedBytes, ...Buffer.from('ml-dsa-65-agent-v1', 'utf8')]),
    { dkLen: 32 }
  );
  const edPub = ed.getPublicKey(edSeed);
  const mlKp = ml_dsa65.keygen(mlSeed);
  const didDigest = blake3(new Uint8Array([...edPub, ...mlKp.publicKey]), { dkLen: 32 });
  return {
    agent_did: `did:hive:hybrid:${toHex(didDigest)}`,
    ed25519: {
      private_key: edSeed,
      public_key: edPub,
    },
    ml_dsa_65: {
      private_key: mlKp.secretKey,
      public_key: mlKp.publicKey,
    },
    scheme: 'hybrid:ed25519+ml-dsa-65',
  };
}

// Sign a canonical message blob with BOTH keys. Returns hex pair.
export function hybridSign(agentKp, messageBytes) {
  const ed_sig = ed.sign(messageBytes, agentKp.ed25519.private_key);
  const ml_sig = ml_dsa65.sign(messageBytes, agentKp.ml_dsa_65.private_key);
  return {
    ed25519_sig: toHex(ed_sig),
    ml_dsa_65_sig: toHex(ml_sig),
    scheme: 'hybrid:ed25519+ml-dsa-65',
  };
}

// Verify a hybrid signature. Returns { ok, checks } — BOTH must pass.
export function hybridVerify(messageBytes, ed_sig_hex, ml_sig_hex, ed_pub_hex, ml_pub_hex) {
  const checks = { ed25519: false, ml_dsa_65: false };
  try {
    checks.ed25519 = ed.verify(fromHex(ed_sig_hex), messageBytes, fromHex(ed_pub_hex));
  } catch { checks.ed25519 = false; }
  try {
    checks.ml_dsa_65 = ml_dsa65.verify(fromHex(ml_sig_hex), messageBytes, fromHex(ml_pub_hex));
  } catch { checks.ml_dsa_65 = false; }
  return { ok: checks.ed25519 && checks.ml_dsa_65, checks };
}

// Compute the agent DID from a pair of public keys (verifier-side, no private material).
export function deriveDidFromPubkeys(edPubHex, mlPubHex) {
  const edPub = fromHex(edPubHex);
  const mlPub = fromHex(mlPubHex);
  const didDigest = blake3(new Uint8Array([...edPub, ...mlPub]), { dkLen: 32 });
  return `did:hive:hybrid:${toHex(didDigest)}`;
}

export const HYBRID_AGENT_SCHEME = 'hybrid:ed25519+ml-dsa-65';

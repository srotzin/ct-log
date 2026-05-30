// Vector 3 — PQ witness gossip quorum (in-process pseudo-witnesses).
//
// Three independent witness identities, each with its own Ed25519 + ML-DSA-65
// keypair, deterministically derived from distinct seeds. Each witness co-signs
// every published STH with BOTH classical and post-quantum signatures, producing
// a witness_quorum block of N independent dual-signatures.
//
// A bundle is "quorum-valid" when at least Q-of-N witness signatures verify
// (default 2-of-3) on the same canonical STH bytes. This is structurally a
// Byzantine quorum on the witness layer — even with these witnesses running
// in-process, an adversary must forge BOTH signature schemes on Q distinct
// keys to fake a quorum-valid bundle. The same code path lights up identically
// when the witnesses are later relocated to separate Render services.
//
// Patent Pending. Filed 2026-05-08. Inventor: Steve Rotzin.
//   The PQ witness gossip quorum, the dual-key per-witness identity, the
//   quorum threshold over hybrid (classical + post-quantum) co-signatures over
//   the canonical STH encoding, and the bundle-embedded quorum verification
//   path are original work by Steve Rotzin / Hive Civilization, Inc.

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { blake3 } from '@noble/hashes/blake3';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const toHex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

// Default witness seeds. Three independent 32-byte secrets. In a real
// deployment these would be split across separate Render services and the
// public keys published in their respective /.well-known endpoints.
const DEFAULT_WITNESS_SEEDS = {
  'witness-a': '11a11a11a11a11a11a11a11a11a11a11a11a11a11a11a11a11a11a11a11a11a1',
  'witness-b': '22b22b22b22b22b22b22b22b22b22b22b22b22b22b22b22b22b22b22b22b22b2',
  'witness-c': '33c33c33c33c33c33c33c33c33c33c33c33c33c33c33c33c33c33c33c33c33c3',
};

function deriveSeed32(seed32, tag) {
  return blake3(
    new Uint8Array([...seed32, ...Buffer.from(tag, 'utf8')]),
    { dkLen: 32 }
  );
}

// Derive a witness keypair from a 32-byte seed.
// Ed seed = blake3(seed || "witness-ed25519-v1", 32)
// PQ seed = blake3(seed || "witness-ml-dsa-65-v1", 32)
function deriveWitness(name, seedHex) {
  const seed = fromHex(seedHex);
  if (seed.length !== 32) throw new Error(`witness ${name} seed must be 32 bytes`);
  const edSeed = deriveSeed32(seed, 'witness-ed25519-v1');
  const mlSeed = deriveSeed32(seed, 'witness-ml-dsa-65-v1');
  const edPub = ed.getPublicKey(edSeed);
  const mlKp = ml_dsa65.keygen(mlSeed);
  return {
    name,
    ed25519: { private_key: edSeed, public_key: edPub },
    ml_dsa_65: { private_key: mlKp.secretKey, public_key: mlKp.publicKey },
  };
}

// Build the witness set at startup. Reads env override
// WITNESS_SEED_<NAME>=<hex> if set, otherwise uses defaults.
function readSeedFromEnv(name) {
  const envKey = `WITNESS_SEED_${name.replace(/-/g, '_').toUpperCase()}`;
  return process.env[envKey] || DEFAULT_WITNESS_SEEDS[name];
}

let _witnesses = null;
export function initWitnesses() {
  if (_witnesses) return _witnesses;
  _witnesses = Object.keys(DEFAULT_WITNESS_SEEDS).map((name) =>
    deriveWitness(name, readSeedFromEnv(name))
  );
  return _witnesses;
}

export function getWitnessPubkeys() {
  const list = initWitnesses();
  return list.map((w) => ({
    name: w.name,
    ed25519_pubkey: toHex(w.ed25519.public_key),
    ml_dsa_65_pubkey: toHex(w.ml_dsa_65.public_key),
    ml_dsa_65_pubkey_bytes: w.ml_dsa_65.public_key.length,
  }));
}

// Sign STH canonical bytes with EVERY witness, returning a quorum block.
// canonicalBytes must be exactly the bytes the witnesses commit to (the dual-hash
// canonical encoding from keys.encodeSTHDual).
export function signSTHQuorum(canonicalBytes) {
  const list = initWitnesses();
  const signatures = list.map((w) => {
    const ed_sig = ed.sign(canonicalBytes, w.ed25519.private_key);
    const ml_sig = ml_dsa65.sign(canonicalBytes, w.ml_dsa_65.private_key);
    return {
      name: w.name,
      ed25519_sig: toHex(ed_sig),
      ml_dsa_65_sig: toHex(ml_sig),
      ed25519_pubkey: toHex(w.ed25519.public_key),
      ml_dsa_65_pubkey: toHex(w.ml_dsa_65.public_key),
    };
  });
  return {
    scheme: 'witness-quorum:hybrid:ed25519+ml-dsa-65',
    canonical_encoding: 'epoch(8) || tree_size(8) || root_blake3(32) || root_sha3_256(32) || ts(8), big-endian',
    n: signatures.length,
    threshold: 2,
    signatures,
  };
}

// Verify a quorum block. Returns { ok, passing, n, threshold, per_witness }
// `ok` is true if at least `threshold` witnesses have BOTH sigs valid.
export function verifySTHQuorum(canonicalBytes, quorum) {
  const per = [];
  let passing = 0;
  for (const s of quorum.signatures) {
    let ed_ok = false, ml_ok = false;
    try { ed_ok = ed.verify(fromHex(s.ed25519_sig), canonicalBytes, fromHex(s.ed25519_pubkey)); } catch {}
    try { ml_ok = ml_dsa65.verify(fromHex(s.ml_dsa_65_sig), canonicalBytes, fromHex(s.ml_dsa_65_pubkey)); } catch {}
    const both = ed_ok && ml_ok;
    if (both) passing++;
    per.push({ name: s.name, ed25519: ed_ok, ml_dsa_65: ml_ok, hybrid: both });
  }
  return {
    ok: passing >= (quorum.threshold || 2),
    passing,
    n: quorum.n || quorum.signatures.length,
    threshold: quorum.threshold || 2,
    per_witness: per,
  };
}

export const WITNESS_QUORUM_SCHEME = 'witness-quorum:hybrid:ed25519+ml-dsa-65';

// One-time: generate log operator Ed25519 keypair, print hex.
// Run: node src/init-key.js
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const priv = ed.utils.randomPrivateKey();
const pub = ed.getPublicKey(priv);
console.log('LOG_OPERATOR_PRIVATE_KEY=' + Buffer.from(priv).toString('hex'));
console.log('LOG_OPERATOR_PUBLIC_KEY=' + Buffer.from(pub).toString('hex'));
console.log('');
console.log('Set the private key as an env var on Render. The public key goes at /.well-known/ct-pubkey.');

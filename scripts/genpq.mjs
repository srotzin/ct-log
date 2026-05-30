import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from 'node:crypto';
const seed = randomBytes(32);
const { publicKey, secretKey } = ml_dsa65.keygen(seed);
const msg = new TextEncoder().encode('hive-pq-genesis');
const sig = ml_dsa65.sign(msg, secretKey);
const ok = ml_dsa65.verify(sig, msg, publicKey);
if (!ok) { console.error('VERIFY FAILED'); process.exit(1); }
console.log('SEED_HEX=' + Buffer.from(seed).toString('hex'));
console.log('PQ_PUBKEY_HEX=' + Buffer.from(publicKey).toString('hex'));
console.log('PQ_PUBKEY_LEN=' + publicKey.length);
console.log('PQ_SECKEY_LEN=' + secretKey.length);
console.log('PQ_SIG_LEN=' + sig.length);
console.log('VERIFY=OK');

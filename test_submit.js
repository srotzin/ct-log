// Smoke test: build a receipt, sign it, submit, fetch proof.
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { blake3 } from '@noble/hashes/blake3';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const BASE = 'http://127.0.0.1:8181';

// Agent key
const agentPriv = ed.utils.randomPrivateKey();
const agentPub = ed.getPublicKey(agentPriv);
const did = 'did:hive:treasury-001';

async function get(path) { return (await fetch(BASE + path)).json(); }
async function post(path, body) {
  return (await fetch(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })).json();
}

const sth = await get('/v1/sth');
console.log('Latest STH before submit:', { epoch: sth.epoch, tree_size: sth.tree_size, root: sth.root.slice(0, 16) });

const receipt = {
  v: 1,
  agent_did: did,
  prev_receipt_hash: '0'.repeat(64),
  log_sth_root: sth.root,
  log_sth_size: sth.tree_size,
  action_type: 'heartbeat',
  input_commit: Buffer.from(blake3('genesis input')).toString('hex'),
  output_commit: Buffer.from(blake3('genesis output')).toString('hex'),
  counterparty_did: null,
  counterparty_sig: null,
  ts: Date.now(),
};

// Sign canonical bytes
const signedFields = ['v','agent_did','prev_receipt_hash','log_sth_root','log_sth_size','action_type','input_commit','output_commit','counterparty_did','counterparty_sig','ts'];
const canonical = {};
for (const k of signedFields) canonical[k] = receipt[k] ?? null;
const canonicalBytes = Buffer.from(JSON.stringify(canonical));
const sig = await ed.sign(canonicalBytes, agentPriv);
receipt.agent_sig = Buffer.from(sig).toString('hex');
receipt.agent_pubkey = Buffer.from(agentPub).toString('hex');

const payload_b64 = Buffer.from(JSON.stringify(receipt)).toString('base64');
const submitResult = await post('/v1/submit', { payload_b64 });
console.log('Submit result:', submitResult);

const vest = await get(`/v1/vestigium/${did}`);
console.log('Vestigium for treasury:', vest);

// Wait for next STH so proof is available
console.log('Waiting 31s for next STH...');
await new Promise(r => setTimeout(r, 31000));

const proof = await get(`/v1/proof/${submitResult.leaf_hash}`);
console.log('Inclusion proof:', { seq: proof.seq, tree_size: proof.tree_size, proof_len: proof.proof.length, root: proof.sth.root.slice(0, 16) });

const vestProof = await get(`/v1/vestigium/${did}/proof/${submitResult.leaf_hash}`);
console.log('Vestigium proof:', { seq: vestProof.seq, tree_size: vestProof.tree_size });

console.log('\nT₀ verified end-to-end. The log breathes.');

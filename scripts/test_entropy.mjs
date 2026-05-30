import { fetchLatticeEntropy, LATTICE_NAMES, deriveLatticeKey, signWithLatticeKey } from '../src/entropy.js';

const PQ_SEED = '19054212f40472e4d080de662eeb8c51862768ada02b226042a2a842aafed07d';

for (const name of LATTICE_NAMES) {
  try {
    const t0 = Date.now();
    const ent = await fetchLatticeEntropy(name);
    const ms = Date.now() - t0;
    const kp = deriveLatticeKey(PQ_SEED, name);
    console.log(`[${name}] ms=${ms} records=${ent.body.record_count} digest=${ent.entropy_digest_hex.slice(0,32)}... agent_pub=${Buffer.from(kp.pub).toString('hex').slice(0,32)}...`);
  } catch (e) {
    console.log(`[${name}] ERROR ${e.message}`);
  }
}

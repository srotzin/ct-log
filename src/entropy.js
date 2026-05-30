// Lattice entropy aggregators.
//
// Each lattice produces a deterministic entropy digest by fetching a real public
// data source, normalizing into a canonical JSON form, and hashing with BLAKE3.
// The receipt envelope embeds:
//   - lattice_name              : the substrate
//   - entropy_source_url        : URL the fetcher hit
//   - entropy_source_ts         : when the data was fetched (ms)
//   - entropy_records           : canonical normalized records (small)
//   - entropy_digest            : blake3 hex over the canonical JSON of entropy_records
//   - entropy_audit_uri         : public URL for anyone to re-fetch & verify
//
// The receipt is signed by:
//   - the lattice agent (operator-controlled Ed25519, per-lattice key derived from operator seed)
//   - the operator (Ed25519 + ML-DSA-65 / FIPS 204) as witness

import { blake3 } from '@noble/hashes/blake3';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function toHex(u8) { return Buffer.from(u8).toString('hex'); }

// Stable JSON: sorted keys, no whitespace. Same canon as the receipt envelope.
function canonJSON(obj) {
  if (Array.isArray(obj)) return '[' + obj.map(canonJSON).join(',') + ']';
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonJSON(obj[k])).join(',') + '}';
}

async function fetchText(url, timeoutMs = 8000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ac.signal, headers: { 'user-agent': 'hive-entropy/1.0 (+https://thehiveryiq.com)' } });
    if (!r.ok) throw new Error(`HTTP ${r.status} from ${url}`);
    return await r.text();
  } finally { clearTimeout(t); }
}

async function fetchJSON(url, timeoutMs = 8000) {
  return JSON.parse(await fetchText(url, timeoutMs));
}

async function postJSON(url, body, timeoutMs = 8000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: 'POST',
      signal: ac.signal,
      headers: { 'content-type': 'application/json', 'user-agent': 'hive-entropy/1.0 (+https://thehiveryiq.com)' },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status} from ${url}`);
    return await r.json();
  } finally { clearTimeout(t); }
}

// ---------------------------------------------------------------------------
// Wave-Lattice — NOAA NDBC buoy 46026 (San Francisco Bar)
// ---------------------------------------------------------------------------
async function entropyWave() {
  const url = 'https://www.ndbc.noaa.gov/data/realtime2/46026.txt';
  const txt = await fetchText(url);
  const lines = txt.split('\n').filter(l => l && !l.startsWith('#')).slice(0, 12);
  const records = lines.map(l => {
    const c = l.trim().split(/\s+/);
    return {
      ts_utc: `${c[0]}-${c[1]}-${c[2]}T${c[3]}:${c[4]}:00Z`,
      wind_dir_deg: c[5],
      wind_spd_mps: c[6],
      gust_mps: c[7],
      wave_height_m: c[8],
      dominant_period_s: c[9],
      avg_period_s: c[10],
      mean_wave_dir_deg: c[11],
      pressure_hpa: c[12],
      water_temp_c: c[14],
    };
  });
  return {
    lattice: 'wave',
    source_name: 'NOAA NDBC Station 46026 (San Francisco Bar)',
    source_url: url,
    source_protocol: 'NDBC realtime2 plain-text',
    records,
    record_count: records.length,
  };
}

// ---------------------------------------------------------------------------
// Loess-Lattice — USGS seismic feed (M2.5+, past hour)
// Loess = wind-deposited sediment; we anchor to ground motion as the substrate.
// ---------------------------------------------------------------------------
async function entropyLoess() {
  const url = 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_hour.geojson';
  const d = await fetchJSON(url);
  const records = (d.features || []).slice(0, 16).map(f => ({
    id: f.id,
    mag: f.properties.mag,
    place: f.properties.place,
    ts_ms: f.properties.time,
    depth_km: f.geometry.coordinates[2],
    lat: f.geometry.coordinates[1],
    lon: f.geometry.coordinates[0],
  }));
  return {
    lattice: 'loess',
    source_name: 'USGS Earthquake Hazards Program',
    source_url: url,
    source_protocol: 'GeoJSON M2.5+ past hour',
    feed_generated_ms: d.metadata && d.metadata.generated,
    records,
    record_count: records.length,
  };
}

// ---------------------------------------------------------------------------
// Aurora-Lattice — NOAA SWPC planetary K-index (real geomagnetic activity)
// ---------------------------------------------------------------------------
async function entropyAurora() {
  const url = 'https://services.swpc.noaa.gov/json/planetary_k_index_1m.json';
  const d = await fetchJSON(url);
  const tail = d.slice(-12);
  const records = tail.map(r => ({
    ts_utc: r.time_tag,
    kp_index: r.kp_index,
    estimated_kp: r.estimated_kp,
    kp_str: r.kp,
  }));
  return {
    lattice: 'aurora',
    source_name: 'NOAA SWPC Planetary K-index (geomagnetic)',
    source_url: url,
    source_protocol: 'SWPC 1-minute K-index JSON',
    records,
    record_count: records.length,
  };
}

// ---------------------------------------------------------------------------
// RogueWave-Lattice — NOAA Tides & Currents, Seattle station 9447130
// Substrate: anomalies in measured water level (the rogue-wave intuition).
// ---------------------------------------------------------------------------
async function entropyRogueWave() {
  // Pull last hour of 6-minute water-level samples.
  const station = '9447130';
  const url = `https://api.tidesandcurrents.noaa.gov/api/prod/datagetter?product=water_level&application=hive&date=latest&datum=MLLW&station=${station}&time_zone=gmt&units=metric&format=json`;
  const d = await fetchJSON(url);
  const arr = d.data || [];
  const records = arr.slice(-12).map(r => ({
    ts_utc: r.t,
    water_level_m: r.v,
    std_m: r.s,
    flags: r.f,
    quality: r.q,
  }));
  return {
    lattice: 'rogue-wave',
    source_name: `NOAA Tides & Currents · Station ${station} (Seattle)`,
    source_url: url,
    source_protocol: 'CO-OPS Datagetter water-level',
    station_metadata: d.metadata,
    records,
    record_count: records.length,
  };
}

// ---------------------------------------------------------------------------
// Keystone-Lattice — Base mainnet latest block (validator entropy)
// ---------------------------------------------------------------------------
async function entropyKeystone() {
  const url = 'https://mainnet.base.org';
  const resp = await postJSON(url, {
    jsonrpc: '2.0',
    method: 'eth_getBlockByNumber',
    params: ['latest', false],
    id: 1,
  });
  const b = resp.result;
  return {
    lattice: 'keystone',
    source_name: 'Base mainnet (chain id 8453)',
    source_url: url,
    source_protocol: 'JSON-RPC eth_getBlockByNumber latest',
    records: [{
      block_number_hex: b.number,
      block_hash: b.hash,
      parent_hash: b.parentHash,
      state_root: b.stateRoot,
      txs_root: b.transactionsRoot,
      receipts_root: b.receiptsRoot,
      mix_hash: b.mixHash,
      timestamp_hex: b.timestamp,
      base_fee_per_gas_hex: b.baseFeePerGas,
      gas_used_hex: b.gasUsed,
    }],
    record_count: 1,
  };
}

const LATTICES = {
  wave: entropyWave,
  loess: entropyLoess,
  aurora: entropyAurora,
  'rogue-wave': entropyRogueWave,
  keystone: entropyKeystone,
};

export const LATTICE_NAMES = Object.keys(LATTICES);

export async function fetchLatticeEntropy(name) {
  const fn = LATTICES[name];
  if (!fn) throw new Error(`unknown lattice: ${name}`);
  const fetchedAt = Date.now();
  const body = await fn();
  const canon = canonJSON({ ...body, fetched_ms: fetchedAt });
  const digest = blake3(Buffer.from(canon));
  return {
    fetched_ms: fetchedAt,
    body,
    canonical_bytes: Buffer.from(canon),
    entropy_digest_hex: toHex(digest),
  };
}

// Derive a deterministic Ed25519 keypair for the lattice's "agent" identity.
// Seed is sha512(operator_pq_seed || ":lattice:" || name) truncated to 32 bytes.
// This means each lattice has a stable, operator-bound signing identity
// without storing additional secrets — and the binding is auditable via
// the operator PQ pubkey on file.
export function deriveLatticeKey(operatorPqSeedHex, latticeName) {
  const seedMaterial = Buffer.concat([
    Buffer.from(operatorPqSeedHex, 'hex'),
    Buffer.from(`:lattice:${latticeName}`, 'utf8'),
  ]);
  const h = sha512(seedMaterial);
  const priv = new Uint8Array(h).slice(0, 32);
  const pub = ed.getPublicKey(priv);
  return { priv, pub };
}

export function signWithLatticeKey(canonicalBytes, priv) {
  return ed.sign(canonicalBytes, priv);
}

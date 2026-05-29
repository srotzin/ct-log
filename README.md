# Hive CT Log + Vestigium

The substrate. RFC 6962-style Certificate Transparency Merkle log with a per-agent vestigium layer for Proof of Execution Provenance (POEP).

- Append-only Merkle log over BLAKE3
- Signed tree heads every 30 seconds (Ed25519)
- POEP receipt envelope validation + materialization into per-agent vestigium chains
- Sub-millisecond local verification, no network call required after receipt acquisition

See [thehiveryiq.com/poep](https://thehiveryiq.com/poep/) and [thehiveryiq.com/ct](https://thehiveryiq.com/ct/) for the public-facing thesis.

## Endpoints

- `GET /v1/sth` — latest signed tree head
- `POST /v1/submit` — append a payload (auto-indexed as a receipt if shape matches)
- `GET /v1/proof/:leaf_hash` — Merkle inclusion proof against latest STH
- `GET /v1/consistency?from=N&to=M` — consistency proof between two tree sizes
- `GET /v1/entries?start=N&end=M` — range read of raw entries
- `GET /v1/vestigium/:did` — per-agent depth + latest receipt
- `GET /v1/vestigium/:did/proof/:receipt_hash` — receipt inclusion proof
- `POST /v1/vestigium/:did/append` — convenience wrapper around submit, validates DID match
- `GET /v1/vestigium/:did/chain?from=N&limit=M` — range of an agent's receipts
- `GET /.well-known/ct-pubkey` — log operator's Ed25519 public key
- `GET /healthz` — liveness

## Deploy

1. Generate operator key: `node src/init-key.js`
2. Set `LOG_OPERATOR_PRIVATE_KEY` env var to the private key hex
3. Set `STH_CADENCE_MS=30000` (default)
4. Set `PORT=8080` (or whatever Render assigns)
5. Run `npm start`

The log is the floor. The substrate must be running, not specified.

— Hive Civilization

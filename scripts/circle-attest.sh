#!/usr/bin/env bash
# Hive counterparty attestation
# One command. Generates an ephemeral Ed25519 key on your machine,
# signs a fresh receipt envelope, lands it in the public Hive transparency log.
# The receipt extends YOUR vestigium under the DID you choose.
# No persistent state. No network calls except to Hive.
#
# Default (counterparty=test):
#   curl -sSL https://raw.githubusercontent.com/srotzin/ct-log/master/scripts/circle-attest.sh | bash
#
# Custom short name (gives did:<name>:test):
#   COUNTERPARTY=circle curl -sSL https://raw.githubusercontent.com/srotzin/ct-log/master/scripts/circle-attest.sh | bash
#
# Full DID override (gives whatever DID you declare, e.g. did:agent:kimi-k2):
#   DID=did:agent:kimi-k2 curl -sSL https://raw.githubusercontent.com/srotzin/ct-log/master/scripts/circle-attest.sh | bash

set -euo pipefail

CT_LOG="${CT_LOG_URL:-https://ct-log.onrender.com}"
COUNTERPARTY="${COUNTERPARTY:-test}"
DID="${DID:-}"

if [ -n "$DID" ]; then
  PREFILL_URL="${CT_LOG}/v1/attest/prefill?did=${DID}"
  LABEL="$DID"
else
  PREFILL_URL="${CT_LOG}/v1/attest/prefill?counterparty=${COUNTERPARTY}"
  LABEL="did:${COUNTERPARTY}:test"
fi

echo ""
echo "=================================================="
echo "  Hive Counterparty Attestation"
echo "  Signing as: ${LABEL}"
echo "=================================================="
echo ""
echo "Step 1: Fetching prefilled receipt envelope from ${CT_LOG}"

PREFILL=$(curl -fsS "$PREFILL_URL")
if [ -z "$PREFILL" ]; then
  echo "Failed to fetch prefill."
  exit 1
fi

PY=$(command -v python3 || command -v python || true)
if [ -z "$PY" ]; then
  echo "Need python3 in PATH. Install: brew install python3"
  exit 1
fi

# Pass the prefill JSON via env var to Python (heredoc stdin is the script, not the pipe).
export PREFILL_JSON="$PREFILL"
CT_LOG="$CT_LOG" $PY <<'PYEOF'
import json, sys, urllib.request, urllib.error, base64, os

prefill = json.loads(os.environ["PREFILL_JSON"])
canonical = prefill["canonical_json"]
# Trust the server's canonical bytes (sign those exactly). The canonical_json
# field is shown for human readability; canonical_bytes_b64 is what gets signed.
canonical_bytes = base64.b64decode(prefill["canonical_bytes_b64"])

print("")
print(f"  Signing as (DID):  {canonical['agent_did']}")
print(f"  Prior depth:       {prefill['prev_depth']}")
print(f"  Depth after land:  {prefill['new_depth_if_landed']}")
print(f"  Anchored to STH:   epoch {prefill['sth']['epoch']}, tree_size {prefill['sth']['tree_size']}")
print(f"  STH root:          {prefill['sth']['root'][:32]}...")
print(f"  BLAKE3 of bytes:   {prefill['blake3_hex'][:32]}...")
print(f"  Canonical length:  {len(canonical_bytes)} bytes")
print("")
print("Step 2: Generating ephemeral Ed25519 keypair on this machine")

backend = None
try:
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    vk = sk.verify_key
    sig = sk.sign(canonical_bytes).signature
    pub_hex = bytes(vk).hex()
    sig_hex = bytes(sig).hex()
    backend = "pynacl"
except ImportError:
    pass

if backend is None:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        sig = sk.sign(canonical_bytes)
        pub_hex = pub.hex()
        sig_hex = sig.hex()
        backend = "cryptography"
    except ImportError:
        pass

if backend is None:
    print("")
    print("Need either pynacl or cryptography python package. Install one of:")
    print("  pip install pynacl")
    print("  pip install cryptography")
    sys.exit(3)

print(f"  Backend:           {backend}")
print(f"  Counterparty pub:  {pub_hex}")
print(f"  Signature (hex):   {sig_hex[:32]}...{sig_hex[-32:]}")
print("")
print("Step 3: Submitting signed attestation to Hive log")

body = json.dumps({
    "canonical_bytes_b64": prefill["canonical_bytes_b64"],
    "counterparty_pubkey_hex": pub_hex,
    "counterparty_sig_hex": sig_hex,
}).encode()

CT_LOG = os.environ["CT_LOG"]
req = urllib.request.Request(
    f"{CT_LOG}/v1/attest/submit",
    data=body,
    headers={"content-type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        result = json.loads(r.read())
except urllib.error.HTTPError as e:
    print(f"  Submit failed: HTTP {e.code}")
    print(f"  {e.read().decode()}")
    sys.exit(4)

print("")
print("==================================================")
print("  ATTESTATION LANDED")
print("==================================================")
print(f"  Agent DID:         {result['agent_did']}")
print(f"  Vestigium depth:   {result['vestigium_depth']}")
print(f"  Witness (Hive):    {result['witness_did']}")
print(f"  Receipt seq:       {result['seq']}")
print(f"  Receipt hash:      {result['leaf_hash']}")
print(f"  Anchored STH:      epoch {result['sth']['epoch']}, tree_size {result['sth']['tree_size']}")
print(f"  Inclusion proof:   {CT_LOG}{result['receipt_url']}")
print(f"  Next STH in:       {result['next_sth_in_ms']/1000:.0f}s (then receipt is in a signed root)")
print("")
print("Verify anytime, anywhere:")
print(f"  curl {CT_LOG}{result['receipt_url']}")
print("")
print("This receipt is now public, append-only, and verifiable forever.")
print("The ephemeral keypair was destroyed when this process exits.")
print("")
PYEOF

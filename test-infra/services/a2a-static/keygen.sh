#!/bin/sh
# Generate a fresh EC P-256 keypair with openssl, then hand the private key to
# sign_card.py to emit a genuinely JWS-signed A2A v0.3.0 agent card + JWKS.
# Run at image build time (see Dockerfile); a fresh key each build keeps the
# card and JWKS self-consistent without committing any private key material.
set -eu

OUT="${1:-/out}"
mkdir -p "$OUT"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/ec-private.pem

python3 "$(dirname "$0")/sign_card.py" /tmp/ec-private.pem "$OUT/agent-card.json" "$OUT/jwks.json"

rm -f /tmp/ec-private.pem

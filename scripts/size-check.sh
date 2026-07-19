#!/usr/bin/env bash
# Measures the linux/amd64 stripped collector binary size and reports
# whether it has grown beyond the recorded baseline + 10%.
# Run via `make size-check`.
# Blocking gate: returns non-zero if the binary exceeds baseline + 10%.

set -e

cd "$(dirname "$0")/.."

# BASELINE_BYTES recorded from a fresh prototype build below.
# Update this number consciously when a dep change intentionally raises the bar.
BASELINE_BYTES=10920120

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath \
  -ldflags='-s -w' \
  -o "$OUT" \
  ./collector/cmd/agenthound

BYTES=$(wc -c < "$OUT" | tr -d ' ')
LIMIT=$(( BASELINE_BYTES * 110 / 100 ))

echo "collector linux/amd64 size: $BYTES bytes ($((BYTES/1024/1024)) MiB)"
echo "baseline:                   $BASELINE_BYTES bytes"
echo "limit (baseline +10%):      $LIMIT bytes"

fail=0
if [ "$BYTES" -gt "$LIMIT" ]; then
  echo "FAIL: collector binary exceeds baseline + 10%."
  fail=1
fi

exit $fail

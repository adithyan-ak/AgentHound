#!/usr/bin/env bash
# docs-check.sh — build the MkDocs site in --strict mode, which fails on
# orphan pages (present in docs/ but missing from the mkdocs.yml nav), broken
# internal links, and bad anchors. Mirrors the CI Docs job so doc-structure
# breakage is caught locally instead of after merge.
#
# CI enforces the same strict build on every PR that touches docs/** or
# mkdocs.yml (.github/workflows/docs.yml). This target is the local
# equivalent and is intentionally NOT part of `make prerelease` (keeps that
# gate Go/Node-only — no Python dependency).

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v mkdocs >/dev/null 2>&1; then
  echo "docs-check: mkdocs not found on PATH. Install the docs toolchain:"
  echo "    python3 -m venv .venv && . .venv/bin/activate"
  echo "    pip install -r docs/requirements.txt"
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdocs build --strict --site-dir "$tmp/site"
echo "docs-check: strict build OK."

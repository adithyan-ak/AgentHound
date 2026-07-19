#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_INFRA_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${1:-${TEST_INFRA_DIR}/docker-compose.yml}"
SEED_DIR="${TEST_INFRA_DIR}/services/seed"
JUPYTER_FIXTURE_DIR=/home/jovyan/work/agenthound-fixtures

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

compose exec -T workstation sh -s <"${SEED_DIR}/ollama-seed.sh"
compose exec -T workstation sh -s <"${SEED_DIR}/qdrant-seed.sh"
compose exec -T mlflow python - <"${SEED_DIR}/mlflow-seed.py"
compose exec -T litellm python3 /seed/litellm-seed.py
compose exec -T workstation sh -s <"${SEED_DIR}/contextforge-seed.sh"
compose exec -T workstation sh -s <"${SEED_DIR}/cross-service-config-seed.sh"
compose exec -T workstation sh -s <"${SEED_DIR}/openwebui-seed.sh"

# The notebook image is upstream and intentionally unmodified. Copy the authored
# placeholder fixtures after startup so the looter walks the real Contents API.
compose exec -T --user root jupyter mkdir -p "${JUPYTER_FIXTURE_DIR}"
compose cp "${SEED_DIR}/jupyter-notebooks/." \
  "jupyter:${JUPYTER_FIXTURE_DIR}/"
compose exec -T jupyter test -f \
  "${JUPYTER_FIXTURE_DIR}/agenthound-fixture.ipynb"
compose exec -T jupyter test -f \
	"${JUPYTER_FIXTURE_DIR}/data/support-context.md"

# Exercise the collector's offline trusted-key-store path using the genuine
# public key that signed the current A2A card at image-build time.
compose exec -T workstation curl -fsS \
  http://a2a-static/.well-known/jwks.json \
  -o /root/fixtures/a2a-trusted-jwks.json

printf 'Seeded all deterministic service fixtures.\n'

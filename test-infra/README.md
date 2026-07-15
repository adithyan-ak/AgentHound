# Offline collector test infrastructure

This is a local, offline integration stack for exercising the `agenthound`
collector against disposable services. The root `.gitignore` excludes the
entire `/test-infra/` tree, including this README and generated artifacts, so
changes here do not appear in normal `git status` output.

## Requirements

- Apple-silicon Mac with Docker Desktop using Linux/arm64 containers and Docker
  Compose v2 (`docker compose`)
- Bash
- Go 1.25.12 or newer on the host, used to build the collector binary
- `jq` on the host, used by the assertion harness
- Approximately 8 GiB of free Docker memory and 15-25 GiB of free disk

No AgentHound server, Neo4j, PostgreSQL installation, cloud account, API key, or
GPU is required. PostgreSQL used by LiteLLM runs inside the stack.

## Run

From the repository root:

```bash
bash test-infra/run-tests.sh
```

The harness builds `agenthound`, pulls or builds the containers, waits for
health checks, seeds deterministic fixtures, runs the collector scenarios,
checks their JSON with `jq`, and removes the stack and its volumes after a
successful run.

The first run typically downloads about 8-12 GiB of images plus the roughly
350 MiB `qwen2:0.5b` Ollama model, uses about 5-6 GiB of memory at peak, and
takes 10-30 minutes depending on the network and Docker build cache. A warm run
normally takes a few minutes. Treat these as estimates: upstream `latest`
images can change size and startup time.

## Services

All targets are reachable only on the `agenthound-test` bridge network
(`10.20.30.0/24`); the Compose file publishes no host ports.

- Ollama with `qwen2:0.5b`, Qdrant, MLflow, LiteLLM with PostgreSQL, Jupyter,
  and Open WebUI provide the real AI-service fingerprint and loot targets.
- LangServe runs a real deterministic echo chain.
- `mcp-target-admin` uses the official Python MCP SDK and exposes MCP plus a
  shared in-memory admin mutation surface.
- `a2a-static` serves an OpenSSL-generated, JWS-signed card through nginx;
  `a2a-dynamic` uses the A2A Python SDK reference server.
- `vllm-mock` uses Caddy to serve a cited capture of a real vLLM
  `/v1/models` response because vLLM itself requires a supported GPU.
- `workstation` contains the collector, realistic client configurations, and
  disposable files used by config, poison, implant, extract, and campaign
  scenarios.

## Lifecycle, debugging, and artifacts

Keep the stack and mutated test state after the run:

```bash
bash test-infra/run-tests.sh --keep
```

Inspect a kept or failed stack:

```bash
docker compose -f test-infra/docker-compose.yml ps
docker compose -f test-infra/docker-compose.yml logs --tail=200
docker compose -f test-infra/docker-compose.yml logs --tail=200 SERVICE
docker compose -f test-infra/docker-compose.yml exec workstation sh
```

Collector JSON and assertion diagnostics are written beneath
`test-infra/artifacts/`. Failures preserve these files for inspection. The
generated campaign witness is under `test-infra/fixtures/`.

The mutation scenarios are intentionally destructive, but only within
throwaway state:

- MCP tool-description changes are held in the authored target's memory.
- Instruction poison and MCP config implant change canned files inside the
  disposable workstation container and are exercised with reversion.
- Qdrant seeding deletes and recreates only the fixture collections `docs` and
  `chat-history` in the stack's dedicated named volume.
- `docker compose down -v` deletes only this Compose project's named volumes:
  Ollama models, Qdrant storage, and LiteLLM PostgreSQL data.

Do not repoint the harness at production services or replace its fixture mounts
with non-disposable host paths.

## Test-only credentials

Every credential in this directory is a fixture and must never be reused:

- PostgreSQL: `litellm` / `litellm-local-password`
- LiteLLM master key: `sk-local-agenthound-master-key-not-production`
- Provider keys beginning with `sk-placeholder-` or
  `sk-ant-placeholder-`
- Workstation values containing `fixture-only` and notebook/Qdrant placeholder
  keys
- The harness-generated campaign bearer credential and LiteLLM virtual key

The MCP target receives only the campaign credential's SHA-256 hash. The static
A2A signing key is generated during image build and deleted immediately after
the card is signed.

## Cleanup

Remove containers, the bridge network, and all stack volumes:

```bash
docker compose -f test-infra/docker-compose.yml down -v --remove-orphans
```

Remove generated host-side outputs:

```bash
rm -rf test-infra/artifacts
rm -f test-infra/fixtures/witness.json
rm -f test-infra/services/workstation/bin/agenthound
```

Docker images and build cache are retained for faster subsequent runs. Remove
them separately with Docker Desktop only when the disk space is needed.

## Troubleshooting

- **`docker compose` is unavailable:** update Docker Desktop; the legacy
  `docker-compose` command is not used.
- **An image reports an architecture error:** ensure Docker Desktop is running
  Linux/arm64 containers. The stack is designed for Apple silicon, not an
  amd64-only daemon.
- **The network cannot be created:** another Docker network may already use
  `10.20.30.0/24`. Remove the conflicting throwaway network before rerunning;
  changing the subnet also requires updating fixed addresses and assertions.
- **A service stays unhealthy:** inspect its logs with the commands above.
  Open WebUI, LiteLLM migrations, and the first Ollama model pull are normally
  the slowest steps.
- **Disk or memory pressure:** allocate at least 8 GiB to Docker Desktop, free
  15-25 GiB of disk, run the cleanup command, and retry.
- **A rerun sees stale data:** run the cleanup command with `-v`; this resets
  every persistent fixture volume.
- **Assertions fail:** inspect the matching JSON and diagnostics in
  `test-infra/artifacts/`, then rerun with `--keep` to inspect live containers.

# Upstream compatibility harness

The required smoke harness validates the critical collector-to-server path with a real MCP implementation and a minimal PostgreSQL/Neo4j stack:

```bash
make integration
```

It collects a configured bearer credential, proves differential MCP resource access in the local planner, validates the JSON artifact, ingests it manually, and requires a verified finding.

The complete compatibility harness validates the collector and analysis server against all pinned upstream implementations.

It performs:

1. collector and server builds;
2. independent startup and seeding of MCP, A2A, Ollama, vLLM, LangServe, Qdrant, MLflow, LiteLLM, Jupyter, Open WebUI, and ContextForge;
3. one deep active scan of the isolated service network;
4. one targetless stealth scan;
5. assertions over raw credentials, scan execution state, supported service nodes, mode boundaries, access proof, and cleanup;
6. manual ingestion of the active artifact into the production PostgreSQL/Neo4j stack.

Run the complete harness from the repository root:

```bash
make upstream-test
```

Keep the stack and generated `test-infra/artifacts/<run-id>/` directory for investigation:

```bash
bash test-infra/run-tests.sh --keep
```

The services run on the disposable `10.20.30.0/24` Compose bridge. Do not point the seed or verification scripts at production systems. The cold run downloads several pinned service images and a CPU vLLM model.

See [UPSTREAMS.md](UPSTREAMS.md) for immutable versions, sources, and the refresh procedure.

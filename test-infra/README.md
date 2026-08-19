# Unified collector integration harness

This manual Docker harness verifies the released product shape against real upstream implementations:

1. build the collector and server;
2. start and independently seed the pinned MCP, A2A, Ollama, vLLM, LangServe, Qdrant, MLflow, LiteLLM, Jupyter, Open WebUI, and ContextForge fixtures;
3. run one deep active `agenthound scan 10.20.30.0/24`;
4. run one targetless `agenthound scan --stealth`;
5. validate plain raw Credential material, execution journals, supported service nodes, removed extraction/campaign graph types, mode behavior, and zero unresolved cleanup;
6. manually ingest the active artifact into the production PostgreSQL/Neo4j server pair.

Run from the repository root:

```bash
bash test-infra/run-tests.sh
```

Retain the stack and generated `test-infra/artifacts/<run-id>/` directory:

```bash
bash test-infra/run-tests.sh --keep
```

The topology is isolated on the disposable `10.20.30.0/24` Compose bridge. Never repoint its seed scripts at production. The cold run is large because it uses pinned real service images, including CPU vLLM.

The harness intentionally does not test deleted collector commands, witness export, campaigns, engagement state, output-to-stdout, runtime rule bundles, or GGUF extraction.

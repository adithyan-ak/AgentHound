# `agenthound discover` — protocol-discovery for MCP servers and A2A agents

> **Legal notice.** Probing protocol-shape endpoints (HTTP POST of JSON-RPC `initialize`, GET of `/.well-known/agent-card.json`) on hosts you do not control or do not have written authorization to test is a violation of the Computer Fraud and Abuse Act (US, 18 U.S.C. § 1030) and equivalent statutes (Computer Misuse Act 1990 in the UK; § 202a–c in Germany; comparable laws elsewhere). Treat every public IP target with `--allow-public-targets` the same way you would treat an authenticated red-team operation: paper authorization in hand, IR coordination, and a watermarked engagement.

`agenthound discover <CIDR|host|@file>` is the protocol-discovery command. It is the counterpart to `agenthound scan` (which sweeps a fixed AI-service port set and dispatches per-port fingerprinters). Where `scan` answers "is there a vLLM listening on port 8000?", `discover` asks whether an MCP server or A2A agent is present on the configured discovery ports by issuing protocol-shape probes.

## Probes

| Mode | Method | Path | Match condition |
|---|---|---|---|
| MCP | POST | `/` and `/mcp` | JSON-RPC `initialize` response with `jsonrpc: "2.0"` + `result.serverInfo` or `result.capabilities` |
| A2A | GET | `/.well-known/agent-card.json` (fallback `/.well-known/agent.json`) | JSON with `name` AND (`url` OR `supportedInterfaces`) |

Default port sets:

- **MCP**: 3000, 8000, 8080, 8443
- **A2A**: 80, 443, 3000, 8080

Override with `--mcp-ports` / `--a2a-ports`.

## Quick start

```bash
# Both protocols against a private CIDR.
agenthound discover 10.0.0.0/24 --output -

# MCP only.
agenthound discover 10.0.0.0/24 --mcp --output -

# A2A only, against a single host.
agenthound discover 10.0.0.42 --a2a --output -

# Public-IP target — requires AUTHORIZED prompt + watermark.
agenthound discover 198.51.100.0/24 \
    --allow-public-targets \
    --authorization-file ./engagement-authz.pdf \
    --output ./discover-public.json
```

## Output

The output file is a standard ingest envelope. `discover` emits raw `:MCPServer` and `:A2AAgent` nodes with `discovered_via: "protoscan"` and the discovered base URL. The analysis server ingests those facts but does not enumerate the endpoints. To collect tools, resources, and prompts from MCP or skills and delegation from A2A, rerun the collector with `agenthound scan --mcp --url <url>` or `agenthound scan --a2a --target <url>` against each discovered endpoint and ingest that output.

```json
{
  "meta": {
    "version": 4,
    "type": "agenthound-ingest",
    "collector": "scan",
    "collector_version": "1.0.0",
    "timestamp": "2026-07-11T20:00:00Z",
    "scan_id": "...",
    "identity": {
      "scheme": "agenthound_collection_v1",
      "version": 1,
      "collection_point_id": "sha256:...",
      "network_context_id": "sha256:...",
      "quality": "strong",
      "network_quality": "strong",
      "network_class": "private",
      "evidence": [
        {"kind": "os_instance", "digest": "hmac-sha256:..."},
        {"kind": "principal", "digest": "hmac-sha256:..."}
      ],
      "network_evidence": [
        {"kind": "route_private", "digest": "hmac-sha256:..."}
      ]
    },
    "collection": {
      "state": "complete",
      "coverage_keys": ["scan:discover:sha256:..."],
      "outcomes": [{
        "collector": "scan",
        "coverage_key": "scan:discover:sha256:...",
        "target": "10.0.0.0/24",
        "method": "protocol_discovery",
        "state": "complete",
        "items": 3
      }]
    },
    "ruleset": {
      "digest": "sha256:...",
      "load_state": "complete",
      "authenticity": "unverified"
    },
    "identity_schemes": [{
      "entity_kind": "MCPServer",
      "transport": "stdio",
      "scheme": "mcp_stdio_v3_hashed_argv",
      "version": 3
    }],
    "extra": {
      "discover_spec": "10.0.0.0/24",
      "discover_targets": 3,
      "allow_public_targets": false
    }
  },
  "graph": {
    "nodes": [
      {
        "id": "sha256:...",
        "kinds": ["MCPServer"],
        "properties": {
          "endpoint": "http://10.0.0.42:3000",
          "transport": "http",
          "discovered_via": "protoscan",
          "protocol": "mcp",
          "auth_method": "unknown",
          "auth_assurance": "unknown",
          "auth_evidence": "unknown"
        },
        "observation_domains": ["scan:discover:sha256:..."]
      }
    ],
    "edges": []
  }
}
```

## Safety controls

| Control | Default | Override flag | Notes |
|---|---|---|---|
| Public IP space | refused | `--allow-public-targets` + AUTHORIZED prompt | Mirrors `scan`'s gate exactly. |
| CIDRs > /16 | refused | `--allow-large-cidr` | A /24 is ~256 hosts × 4 ports per protocol = ~1k probes; a /16 is ~65k hosts. An absolute ceiling of 1,048,576 hosts (exactly IPv4 `/12`, IPv6 `/108`) applies *even with* `--allow-large-cidr`; split larger ranges into chunks. |
| Link-local | refused (no flag) | n/a | 169.254.x.x and fe80::/10 cannot be routed off-host. |
| Multicast | refused (no flag) | n/a | Not unicast scan targets. |
| Authorization watermark | optional | `--authorization-file <path>` | Path + SHA-256 recorded in envelope `meta.extra`. |

## Concurrency and timeouts

- `--network-scan-concurrency N` — default 50 parallel HTTP probes (hard-clamped to 4096)
- `--timeout T` — default 5s per probe
- `--insecure` — skip TLS verification (for self-signed dev MCP servers; do NOT use in engagements)

## Output volume and cancellation

By default `discover` prints a single summary line — `[discover] <spec>: N endpoint(s)` — and gates the full per-endpoint listing (protocol + URL for each match) behind `--verbose`. On an interactive terminal a single rewriting progress line tracks the probe sweep; it is omitted automatically when output is piped or redirected, and `--quiet` / `AGENTHOUND_QUIET=1` suppresses both the progress line and the summary. None of this affects the JSON written to `--output`.

Ctrl-C (SIGINT) or SIGTERM cancels the probe pool cleanly and writes the endpoints found so far to `--output`, so an interrupted sweep still produces useful JSON rather than dying mid-write.

## Combining with `scan` and `loot`

The intended workflow is:

```bash
# 1. Find AI services (Ollama, LiteLLM, etc.) and fingerprint them.
agenthound scan 10.0.0.0/24 --output - | agenthound-server ingest -

# 2. Find MCP servers and A2A agents.
agenthound discover 10.0.0.0/24 --output - | agenthound-server ingest -

# 3. Inventory a known LiteLLM gateway's credential evidence.
agenthound loot 10.0.0.20:4000 --type litellm --master-key sk-... \
    --engagement-id RTV-2027 --output - | agenthound-server ingest -

# 4. Loot a discovered Ollama for model inventory + modelfile.
agenthound loot 10.0.0.10:11434 --type ollama \
    --engagement-id RTV-2027 --output - | agenthound-server ingest -
```

After each ingest the `cross_service_credential_chain` post-processor correlates
an observed Config credential with the operator-supplied LiteLLM master key by
`value_hash`. It can then surface `:CAN_REACH` findings to provider or virtual-key
references exposed by that gateway. Masked/hashed targets remain reference-only;
the edge does not establish possession of their plaintext.

## See also

- [`agenthound scan` operator guide](scanner.md)
- [LiteLLM Looter operator guide](loot/litellm.md)
- [Security model](security.md) — full threat model
- `modules/protoscan/scanner.go` — implementation

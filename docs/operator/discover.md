# `agenthound discover` — protocol-discovery for MCP servers and A2A agents

> **Legal notice.** Probing protocol-shape endpoints (HTTP POST of JSON-RPC `initialize`, GET of `/.well-known/agent-card.json`) on hosts you do not control or do not have written authorization to test is a violation of the Computer Fraud and Abuse Act (US, 18 U.S.C. § 1030) and equivalent statutes (Computer Misuse Act 1990 in the UK; § 202a–c in Germany; comparable laws elsewhere). Treat every public IP target with `--allow-public-targets` the same way you would treat an authenticated red-team operation: paper authorization in hand, IR coordination, and a watermarked engagement.

`agenthound discover <CIDR|host|@file>` is the v0.3 protocol-discovery verb. It is the counterpart to `agenthound scan` (which sweeps a fixed AI-service port set and dispatches per-port fingerprinters). Where `scan` answers "is there a vLLM listening on port 8000?", `discover` answers "is there an MCP server somewhere on this network, on whatever port it happens to bind?" — by issuing the protocol-shape probes that uniquely identify each protocol.

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

The output file is a standard ingest envelope. `discover` emits raw `:MCPServer` and `:A2AAgent` nodes with `discovered_via: "protoscan"` and the discovered base URL. The full enumeration (tools, resources, prompts for MCP; skills, delegate-to graph for A2A) happens when you re-run `agenthound scan --mcp --url <url>` / `--a2a --target <url>` against the discovered endpoints, OR when the server's downstream `mcp.enumerate` / `a2a.enumerate` modules consume the same envelope.

```json
{
  "meta": {
    "version": 1,
    "type": "agenthound-ingest",
    "collector": "scan",
    "scan_id": "...",
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
          "protocol": "mcp"
        }
      }
    ]
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

The intended sequence for the v0.3 demo arc is:

```bash
# 1. Find AI services (Ollama, LiteLLM, etc.) and fingerprint them.
agenthound scan 10.0.0.0/24 --output - | agenthound-server ingest -

# 2. Find MCP servers and A2A agents.
agenthound discover 10.0.0.0/24 --output - | agenthound-server ingest -

# 3. Loot a known LiteLLM gateway for upstream provider keys.
agenthound loot 10.0.0.20:4000 --type litellm --master-key sk-... \
    --engagement-id RTV-2027 --output - | agenthound-server ingest -

# 4. Loot a discovered Ollama for model inventory + modelfile.
agenthound loot 10.0.0.10:11434 --type ollama \
    --engagement-id RTV-2027 --output - | agenthound-server ingest -
```

After each ingest the `cross_service_credential_chain` post-processor folds the `value_hash` joins, surfacing `:CAN_REACH` paths from agents to upstream provider credentials via the LiteLLM gateway — the credential-chain finding the demo lab is built around.

## See also

- [`agenthound scan` operator guide](scanner.md)
- [LiteLLM Looter operator guide](loot/litellm.md)
- [Security model](security.md) — full threat model
- `modules/protoscan/scanner.go` — implementation

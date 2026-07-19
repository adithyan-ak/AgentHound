# `agenthound scan` — network scanner operator guide

> **Authorized targets only.** Scanning IP space without written authorization may violate CFAA-style laws (US 18 USC 1030, UK Computer Misuse Act, equivalent statutes in most jurisdictions). The scanner refuses public IP space without `--allow-public-targets`, and that flag itself requires interactive `AUTHORIZED` confirmation. The authorization-file watermark exists so you have an auditable record of what authorization covered which scan. Use a controlled lab environment for testing; coordinate with target IR/security teams for engagements.

The network scanner is the v0.2 entry point for active discovery. It performs a bounded TCP port sweep across a CIDR or host list, then dispatches the registered fingerprinters at each open `(host, port)` pair to identify AI services. Output is the same ingest envelope the existing collectors produce, so `agenthound-server ingest` accepts it through the same path.

The scanner is intentionally narrow — AI services on a fixed port set, not a general-purpose Nmap replacement. AgentHound starts where Nmap stops.

---

## Quick start

```bash
# Smallest invocation. Private CIDR, no authorization prompt needed.
agenthound scan 10.0.0.0/24

# Stream JSON to stdout for piping.
agenthound scan 10.0.0.0/24 --output -

# Single host.
agenthound scan 10.0.0.42

# Public IP space requires explicit override AND interactive AUTHORIZED prompt.
agenthound scan 1.1.1.1 --allow-public-targets --authorization-file ./engagement-2026-DC34.pdf

# Custom port set. Every registered fingerprinter still evaluates each open port.
agenthound scan 10.0.0.0/24 --ports 11434,4000

# Tune probe concurrency.
agenthound scan 10.0.0.0/24 --network-scan-concurrency 100
```

---

## Default port set

The scanner probes seven ports by default. Every port in this set now has a shipped fingerprinter:

| Port | Service | Fingerprinter status |
|------|---------|---------------------|
| 11434 | Ollama | shipped |
| 4000 | LiteLLM | shipped |
| 8000 | vLLM AND LangServe (port collision; fingerprint dispatch resolves) | shipped (both) |
| 6333 | Qdrant | shipped |
| 5000 | MLflow | shipped |
| 8888 | Jupyter | shipped |
| 3000 | Open WebUI | shipped |

Port assignments are ordering hints, not dispatch gates. At every open
`(host, port)` endpoint, the hinted fingerprinters run first and every remaining
registered fingerprinter follows exactly once. Override with
`--ports 11434,4000` to choose which ports receive the TCP-open check; a LiteLLM
gateway or vLLM instance on either port is still evaluated by both relevant
fingerprinters.

---

## Safety controls

The scanner ships with three layered controls that match the OPSEC posture of the rest of AgentHound — transparent assessment, not an evasion implant.

### 1. `--allow-public-targets` + AUTHORIZED prompt

Without `--allow-public-targets`, public IP space is refused outright. With the flag, an interactive prompt blocks the scan:

```
[scan] --allow-public-targets is set. About to scan: 1.1.1.1
[scan] Scanning IP space without written authorization may violate CFAA-style laws.
[scan] If you have written authorization for these targets, type AUTHORIZED to proceed:
```

Anything other than the literal string `AUTHORIZED` aborts with a non-zero exit. There is no `--yes` shortcut — the friction is intentional.

### 2. `--allow-large-cidr`

CIDRs larger than `/16` (IPv4) or `/112` (IPv6) require `--allow-large-cidr`. A typo like `10.0.0.0/8` (16 million hosts) without the override returns an explicit error explaining the cap. With the flag, the scanner enumerates without further prompting — the operator has already explicitly opted in.

An **absolute host ceiling of 1,048,576** (exactly an IPv4 `/12` or IPv6 `/108`) applies *even with* `--allow-large-cidr`: the override raises the prefix gate but cannot request an unbounded enumeration. Specs above the ceiling — including a standard IPv6 `/64` or `0.0.0.0/0` — are refused outright before any allocation, because the host list is materialized in memory. Split very large ranges into chunks at or below the ceiling.

### 3. `--authorization-file` watermark

Pass the path to a written-authorization document and the scanner records the path and the file's SHA-256 in the scan-output JSON's top-level `meta.extra.authorization` block:

```json
{
  "meta": {
    "extra": {
      "authorization_file_path": "./engagement-2026-DC34.pdf",
      "authorization_file_sha256": "a3f9c2...",
      "allow_public_targets": true,
      "network_scan_spec": "10.0.0.0/24"
    }
  }
}
```

The CLI does NOT validate the signature — that is not its job. The watermark exists so downstream analysis tools can refuse to operate on watermark-less public-IP scans, and so the operator has a paper trail. Keep the authorization PDF alongside engagement records; pin the SHA-256 in your engagement notes.

### Always-refused targets

Three address classes are refused unconditionally — no flag turns them on:

- **Link-local** — IPv4 `169.254.0.0/16` (excluding the `169.254.169.254` cloud-metadata literal, which is treated as private), IPv6 `fe80::/10`.
- **Multicast** — IPv4 `224.0.0.0/4`, IPv6 `ff00::/8`.
- **Loopback CIDRs greater than /32** — refusing `127.0.0.0/8` keeps a typo from accidentally flooding the local stack.

The reasoning: link-local doesn't route off-host, multicast isn't a unicast scanning target, and any of these in a CIDR sweep is operator error.

---

## Output

The scanner writes one ingest envelope per invocation. Default location is `./scan-<scan_id>.json`. Pass `--output <path>` to choose; pass `--output -` to stream to stdout for piping into `agenthound-server ingest -`.

The envelope contains:

- `meta` — scan-id, timestamp, collector identity, plus the authorization watermark when applicable.
- `graph.nodes` — `:Host` nodes for every host with at least one open port, plus per-service nodes for every fingerprint match (e.g. `:OllamaInstance:AIService`, `:LiteLLMGateway:AIService`).
- `graph.edges` — any evidence-backed relationships emitted by a
  fingerprinter. The current network fingerprints identify service nodes; they
  do not infer backend `EXPOSES` relationships from unauthenticated version or
  application-shape probes.

---

## Operational notes

**Progress and output volume.** By default the scanner prints a single summary line — `[scan] <spec>: N host(s) with at least one open port` — followed by the per-match fingerprint lines and a fingerprint summary. The full per-host listing (open ports + candidate kinds for every host) is gated behind `--verbose`, because a `/24` sweep over a bridge or VPN can otherwise emit hundreds of near-identical lines. When stderr is an interactive terminal, a single rewriting progress line tracks the port sweep and the fingerprint phase; it is omitted automatically when output is piped or redirected (so logs stay clean) and when `--quiet` / `AGENTHOUND_QUIET=1` is set. Progress and summaries go to stderr and never affect the JSON written to `--output`.

**Cancellation.** Ctrl-C (SIGINT) or SIGTERM cancels scheduling and active probes. On interrupt the scan skips any unstarted fingerprint work and writes a partial envelope to `--output`; `discover` writes the endpoints found so far. Partial coverage is intentionally non-destructive during ingest.

**False positives on private networks with weird routing.** If your dev machine runs Tailscale / a corporate VPN / CGNAT routing, TCP connect probes against unrouted private IPs can return success because the kernel's connect path catches the SYN locally. The scanner reports what it sees at the TCP layer; the fingerprinters in the next step are the actual correctness layer (an open port that doesn't speak Ollama produces no `OllamaInstance` node).

**Concurrency.** Default `--network-scan-concurrency` is 50 — tuned for laptop-class machines. Non-positive values normalize to 50. TCP workers clamp at 4096; the more expensive HTTP fingerprint phase clamps at 64 workers and keeps only a bounded reorder window in flight. Increase on dedicated lab infrastructure; back off if the target subnet has rate-limiting devices.

**Fingerprint completeness.** A bounded, fully read response whose matcher
finishes and does not match is a real negative. Connection/DNS/TLS failures,
timeouts, cancellation, redirects (which remain unfollowed), authentication challenges,
transient statuses, oversized/incomplete bodies, and matcher errors are
indeterminate. The artifact records a partial `fingerprint` outcome on the same
network coverage domain, so production ingestion cannot reconcile away a
service merely because a transient probe failed.

**Concurrency vs. `--scan-concurrency`.** Two separate knobs. `--scan-concurrency` (default 5) controls MCP/A2A enumeration worker count when running the legacy `agenthound scan` (no positional arg) flow. `--network-scan-concurrency` (default 50) controls the network probe pool. Different cost profiles — MCP/A2A do JSON-RPC handshakes; network probes do raw TCP connects.

**TLS.** The network-scan fingerprint probes are HTTP today; HTTPS coverage is not yet wired into the network scanner. The `--insecure` flag applies only to the legacy local MCP/A2A collectors (`scan --mcp` / `scan --a2a`), not to the network sweep — a fingerprinter that needs a TLS handshake would declare its own per-module flag via `FlagsModule`.

---

## Verification

```bash
# Public IP without the flag — expected to error.
agenthound scan 1.1.1.1 2>&1 | grep "public IP space refused"

# Link-local — expected to error even with --allow-public-targets.
agenthound scan fe80::1 --allow-public-targets

# Large CIDR without override — expected to error.
agenthound scan 10.0.0.0/8 2>&1 | grep "larger than the safe cap"

# /30 private — expected to succeed and produce JSON.
agenthound scan 10.0.0.0/30 --output /tmp/scan.json
cat /tmp/scan.json | jq '.meta'
```

---

## See also

- [LiteLLM looting](loot/litellm.md) — extracting credentials from a fingerprinted LiteLLM gateway.
- [Rules bundles](rules-bundle.md) — out-of-band fingerprint rule updates (`--rules-bundle`).
- [Security model](security.md) — overall AgentHound threat model.

# `agenthound scan` — network scanner operator guide

> **Authorized targets only.** Scanning IP space without written authorization may violate CFAA-style laws (US 18 USC 1030, UK Computer Misuse Act, equivalent statutes in most jurisdictions). The scanner refuses public IP space without `--allow-public-targets`, and that flag itself requires interactive `AUTHORIZED` confirmation. The authorization-file watermark exists so you have an auditable record of what authorization covered which scan. Use the controlled lab (`docker/demo/`) for testing; coordinate with target IR/security teams for engagements.

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

# Custom port set (skip ports we don't have fingerprinters for).
agenthound scan 10.0.0.0/24 --ports 11434,4000

# Tune probe concurrency.
agenthound scan 10.0.0.0/24 --network-scan-concurrency 100
```

---

## Default port set

The scanner probes seven ports by default — every port in this set has a v0.2+ fingerprinter or is reserved for v0.3/v0.4:

| Port | Service | Fingerprinter status |
|------|---------|---------------------|
| 11434 | Ollama | **v0.2 — shipped** |
| 4000 | LiteLLM | **v0.2 — shipped** |
| 8000 | vLLM AND LangServe (port collision; fingerprint dispatch resolves) | v0.3 (vLLM), v0.4 (LangServe) |
| 6333 | Qdrant | v0.4 |
| 5000 | MLflow | v0.4 |
| 8888 | Jupyter | v0.3 |
| 3000 | Open WebUI | v0.3 |

Hosts with open ports for which no fingerprinter ships in your binary version emit no node. The open-port set is captured in `Target.Meta["open_ports"]` so a future re-fingerprint against the same scan output can populate the missing services without a fresh scan.

Override with `--ports 11434,4000` to probe a custom subset. The fingerprint dispatcher only runs against ports the scanner observed open, so an unfingerprintable port produces no false positives.

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
- `graph.edges` — `RUNS_ON` edges from each service node to its host, plus any edges the fingerprinters chose to emit (the v0.3 Open WebUI fingerprinter emits an `EXPOSES` edge to its discovered backend Ollama).

---

## Operational notes

**Cancellation.** Ctrl-C cancels the worker pool cleanly. The producer stops queueing tasks before the next port probe; in-flight probes drain to completion (3-second timeout). Partial results are written to `--output` so a long-running scan that gets interrupted still produces useful JSON.

**False positives on private networks with weird routing.** If your dev machine runs Tailscale / a corporate VPN / CGNAT routing, TCP connect probes against unrouted private IPs can return success because the kernel's connect path catches the SYN locally. The scanner reports what it sees at the TCP layer; the fingerprinters in the next step are the actual correctness layer (an open port that doesn't speak Ollama produces no `OllamaInstance` node).

**Concurrency.** Default `--network-scan-concurrency` is 50 — tuned for laptop-class machines. Increase on dedicated lab infrastructure; back off if the target subnet has rate-limiting devices.

**Concurrency vs. `--scan-concurrency`.** Two separate knobs. `--scan-concurrency` (default 5) controls MCP/A2A enumeration worker count when running the legacy `agenthound scan` (no positional arg) flow. `--network-scan-concurrency` (default 50) controls the network probe pool. Different cost profiles — MCP/A2A do JSON-RPC handshakes; network probes do raw TCP connects.

**TLS.** The probes are HTTP today. v0.3 adds HTTPS coverage when the fingerprinters need it (some services bind TLS by default). The `--insecure` flag from the legacy collector flow does not apply to the network scanner — fingerprinters that opt into TLS handshakes will declare their own per-module flag via `FlagsModule` (v0.3).

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

- [`docs/loot-litellm.md`](loot-litellm.md) — extracting credentials from a fingerprinted LiteLLM gateway.
- [`docs/plans/sprint3-offensive-primitives.md`](plans/sprint3-offensive-primitives.md) Section 9 — full risk model and mitigation rationale.
- [`docs/security.md`](security.md) — overall AgentHound threat model.
# `--rules-bundle` — out-of-band fingerprint rule updates

The fingerprint rules engine ships rules embedded in the AgentHound binary (`sdk/rules/builtin/fingerprints/*.yaml`). v0.3 adds a `--rules-bundle <path>` override so operators can pick up rule fixes without rebuilding the collector.

> **The operator is responsible for verifying the cosign signature on the bundle BEFORE pointing AgentHound at it.** v0.3 ships with optional verification — the loader does not call cosign automatically. Mandatory signature verification (refuse to load unsigned bundles) lands in v0.5 once the release pipeline has cut at least one bundle.

---

## Quick start

```bash
# Download a published bundle.
gh release download rules-v2026.06.01 \
    --repo adithyan-ak/agenthound \
    --pattern 'agenthound-rules-*.tar.gz*'

# Verify the cosign signature BEFORE running anything.
cosign verify-blob \
    --certificate agenthound-rules-rules-v2026.06.01.tar.gz.pem \
    --signature agenthound-rules-rules-v2026.06.01.tar.gz.sig \
    --certificate-identity-regexp 'https://github.com/.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    agenthound-rules-rules-v2026.06.01.tar.gz

# Use the bundle in any command that runs fingerprinters.
agenthound --rules-bundle ./agenthound-rules-rules-v2026.06.01.tar.gz scan 10.0.0.0/24

# Or point at a directory of YAML files (during development / lab work).
agenthound --rules-bundle ./my-custom-rules/ scan 10.0.0.0/24

# Env var alternative.
AGENTHOUND_RULES_BUNDLE=./bundle.tar.gz agenthound scan 10.0.0.0/24
```

---

## Override semantics

The bundle merges into the embedded rule set with **same-id rules from the bundle winning**:

| Embedded rule | Bundle rule | Effective rule |
|---|---|---|
| `id: ollama` | (absent) | embedded |
| `id: ollama` | `id: ollama` | bundle (override wins) |
| (absent) | `id: my-custom` | bundle (additive) |

This is what you want for hot-fixing a broken regex in a shipped rule, or for adding a new fingerprinter rule the binary's rule set doesn't yet include.

---

## Bundle format

A bundle is one of:

- A directory containing `*.yaml` files (one rule per file).
- A `.tar.gz` archive containing `fingerprints/*.yaml` entries.

The loader reads `*.yaml` and skips other file types. Each YAML file follows the same shape as the embedded rules at `sdk/rules/builtin/fingerprints/`:

```yaml
id: ollama-hotfix-2026-06
name: Ollama (CVE-2026-XXXXX hotfix)
description: refines the Ollama version regex to catch the new patch series
version: 2
service_kind: ollama
probes:
  - method: GET
    path: /api/version
    matchers:
      - type: http_status
        status_code: 200
      - type: json_path
        path: "$.version"
        regex: '^\d+\.\d+\.\d+(-rc\d+)?$'
    captures:
      version: "$.version"
emit:
  node_kinds:
    - OllamaInstance
    - AIService
  properties:
    service_kind: ollama
    auth_method: none
    is_anonymous_loot: "true"
    version: "{capture:version}"
```

Rule IDs MUST be globally unique within a bundle (and across the bundle + embedded merge — the bundle's same-id rule wins, but two same-id rules within one bundle is a load-time conflict).

---

## Release cadence

Bundles are published by the `rules-bundle.yml` GitHub Actions workflow. Triggers:

- **`workflow_dispatch`** — manual release, used for ad-hoc rule fixes.
- **`on: push: tags: ['rules-v*']`** — pushing a `rules-vYYYY.MM.DD` tag automatically cuts a release.

There is **no `on: schedule` trigger**. Bundles are content-driven — a no-changes month produces no bundle. An empty release would confuse cosign verification on the consumer side.

The release artifacts:

- `agenthound-rules-<tag>.tar.gz` — the bundle.
- `agenthound-rules-<tag>.tar.gz.sha256` — checksum.
- `agenthound-rules-<tag>.tar.gz.sig` — cosign keyless signature.
- `agenthound-rules-<tag>.tar.gz.pem` — cosign keyless certificate.

---

## Troubleshooting

**Bundle doesn't load at all.** Check the path. `agenthound --rules-bundle <path>` surfaces the error from `LoadFingerprintBundle` if the path doesn't exist or doesn't unpack. Check the format with `tar -tzf <bundle>.tar.gz` showing one or more `*.yaml` entries.

**Bundle loads but my override doesn't take effect.** Same-id-wins requires the bundle's rule ID to match the embedded rule ID exactly. Check the embedded set with `agenthound rules list`.

**Bundle loads but a rule is silently dropped.** The loader skips files that fail YAML parsing. Run `agenthound rules validate <yaml-path>` against each file in your bundle to catch parse errors. Per-file size cap is 1 MiB.

**Cosign verification fails.** The `--certificate-identity-regexp` in the example matches GitHub Actions OIDC. If you forked the repo and re-released, your cert identity will differ — adjust the regex. Time skew can cause verification failures if your machine clock is off; sync NTP.

---

## See also

- `sdk/rules/bundle.go` — implementation of `LoadFingerprintBundle` and `MergeFingerprintRules`.
- `.github/workflows/rules-bundle.yml` — the release pipeline.
- [`docs/scanner.md`](scanner.md) — the network scanner that consumes fingerprint rules.

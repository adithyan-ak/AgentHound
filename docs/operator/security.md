# AgentHound — security model and threat-model commitments

## What AgentHound is

AgentHound is a transparent, authorized-assessment offensive security
framework for AI agent infrastructure. The collector runs recon,
enumeration, credential looting, and reversible exploitation; the server
builds the graph and computes attack paths. Operators run it against
systems they have been authorized to assess.

## What AgentHound is not

- **Not an evasion implant.** The collector is a 9 MiB Go binary
  literally named `agenthound`. EDR products will detect it on sight.
  We do not ship binary renaming, packing, native compiler chains, or
  syscall-level evasion. If an engagement requires evasion, the right
  tools are Sliver, Mythic, or a custom implant — and you can shuttle
  AgentHound's JSON output through that channel.
- **Not a C2 framework.** There is no server-to-collector control
  channel. The collector is a one-shot CLI: it runs, emits JSON,
  exits.
- **Not a multi-user team server.** The server is single-user and
  intentionally has no authentication at the application layer.

## Single-user server posture

`agenthound-server` binds to `127.0.0.1:8080` by default. This is the
primary security control:

- Anyone with network access to the bound interface can read the
  graph: there is no login, no RBAC, no per-user data scoping.
- For remote access, use a control mechanism the operator already
  trusts: WireGuard / Tailscale / OpenVPN, an SSH tunnel
  (`ssh -L 8080:localhost:8080 host`), or a reverse proxy with mTLS
  in front of the application.
- **Do not** expose the server on `0.0.0.0` or behind plain HTTP on
  the public internet. The application is not designed for that
  threat model and never will be.

If a multi-tenant team server is what you need, fork before this
commit (auth lived in `internal/auth/` until then) — but expect to
maintain it yourself. The project direction is single-user-first.

## Origin guard on mutating endpoints

Although the server is single-user, the operator's *browser* is not.
A malicious tab open in the same browser session can auto-submit a
cross-origin POST to `127.0.0.1:8080` and try to run arbitrary
Cypher or ingest attacker-chosen data. To shut that drive-by path,
`agenthound-server` runs an **Origin allowlist** on every mutating
endpoint (`OriginGuard`):

- Browsers attach `Origin: <scheme>://<host>:<port>` to every
  cross-origin POST (and to every same-origin non-GET) per the Fetch
  spec. The middleware compares the header to the allowlist (default
  `http://localhost:8080` and `http://127.0.0.1:8080`, configurable
  via `AGENTHOUND_CORS_ORIGINS`). A foreign `Origin` (e.g. a tab on
  `evil.com`) → `403 Forbidden`. The string `Origin: null`
  (sandboxed iframes, `data:` / `file:` URLs) is also rejected.
- Requests with **no** `Origin` header pass through. This is the
  non-browser caller — `curl`, the `agenthound` CLI, a cron pipeline.
  Same-host processes are inside the trust boundary by design:
  AgentHound is single-user; if an attacker has shell access on the
  box they can do worse than POST to `/ingest`.
- Read endpoints (graph reads, findings, prebuilt queries, rules,
  health, docs) stay open. Localhost-only reads on a single-user box
  are fine; gating them would force the UI to plumb auth through
  every TanStack Query call for no security gain.
- `agenthound-server` CLI subcommands (`ingest`, `query`) call the
  pipeline / reader directly and do **not** speak HTTP, so they
  bypass OriginGuard entirely.

The allowlist is shared with CORS — one env var, one source of truth.
CORS still enforces `AllowCredentials: false` so a hostile origin
cannot ride ambient cookies even if one were ever introduced.

### Non-loopback binds

Binding `agenthound-server` to anything other than loopback (`0.0.0.0`
or a LAN address) puts mutating endpoints in front of anyone who can
spoof an `Origin` header — trivial for a LAN attacker with `curl`.
The server logs a `WARN` on startup in this case. **Don't do it.**
For remote access use a VPN, an SSH tunnel
(`ssh -L 8080:localhost:8080 host`), or a reverse proxy with mTLS.

### Triage state retention

Triage decisions written via `PATCH /findings/triage/{fingerprint}` live
in the Postgres `finding_triage` table, keyed by the finding fingerprint.
This table has **no foreign key** to the per-scan `findings` snapshot: an
analyst's `accepted-risk` / `false-positive` decisions deliberately
survive scan deletion and re-detection, so deleting a scan (or re-running
a collector) does not silently re-surface a finding that was already
adjudicated. Operators who want a clean slate must clear `finding_triage`
explicitly.

Scan deletion is deliberately history-only. It never issues a Neo4j delete or
interprets last-writer `scan_id` as ownership. The API rejects pending/running
scans, scans referenced by active coverage heads, and the currently published
posture revision with `409`.

## Collector network behaviour

The collector makes outbound network calls to:

1. **Targets specified by the operator** — `--target`, `--targets`,
   `--config`, `--url`, or paths discovered by `--discover`.
2. **A2A v1 signature key URLs declared by those targets** — protected-header
   `jku` retrieval is enabled unless `--no-verify-jwks` is set. It is
   HTTPS-only across redirects, validates TLS identity even when target
   collection uses `--insecure`, refuses link-local/cloud-metadata addresses,
   rejects fragments, is response- and per-card-work-bounded, and receives no
   target authorization header.

There is no telemetry, phone-home, version-check ping, crash reporting, or
upload to a central server.

Scan output is written to a local file (or to stdout via `--output -`).
Transport to the operator's analysis box is the operator's
responsibility — typically a file copy, an SSH pipe
(`agenthound scan --output - | ssh op-box 'agenthound-server ingest -'`),
or a drag-drop into the UI's `Scan Manager → Import scan` dialog. The
collector does not initiate any connection back to a server.

`scripts/deps-check.sh` enforces the dependency boundary: the
collector binary cannot link `chi`, `pgx`, `neo4j-go-driver`, or any
server-only code. Reviewers can verify with `go list -deps` that no
hidden network code crept in via a transitive dep.

## Credential handling

The Config Collector parses MCP client config files which often
contain API keys, OAuth tokens, and database passwords. Default
behaviour:

- Credential **values** are SHA-256 hashed at parse time. The hash is
  stored on the `Credential` node; the raw value never lands in the
  scan JSON.
- `--include-credential-values` opts into raw values. Use this only
  for offline audit work. The output file (containing raw secrets)
  has no transport-layer protection — protect the file at rest.
- Credential identity is not exposure. Nodes record `material_status` and
  `exposure_status`; masked LiteLLM provider references and returned one-way
  hashes are excluded from exposure counts, entropy, and rotation claims.
- Missing auth, host scope, sensitivity, or pinning evidence remains
  `unknown`. It must not be interpreted as anonymous, public, low sensitivity,
  unpinned, or clean.

### Campaign runner: out-of-band credential material

The `agenthound campaign --scenario cred-reach` runner needs an **executable**
credential (the raw secret) to send the authed probe, but it must never persist
or log it. Its handling is deliberately stricter than `--include-credential-values`:

- **Out of band only.** The material is supplied via an environment variable
  (`AGENTHOUND_CAMPAIGN_CREDENTIAL`, the default) or stdin (`--credential-stdin`).
  It is **never** a CLI flag — flags leak into process listings (`ps`), shell
  history, and container inspect output. Do **not** use
  `--include-credential-values` for the campaign path.
- **Local hash-match, never serialized.** The runner hashes the material locally
  with AgentHound's SHA-256 credential contract and requires an **exact match** to
  the witness `value_hash`. The raw value is never written to the graph, the
  emitted evidence, the scan output, or logs. A hash-only credential (no
  executable material, or a synthetic `merge_key=identity` reference) is a
  **precondition failure — not runnable**, distinct from an `indeterminate`
  probe outcome.
- **Endpoint binding before networking.** Surrounding whitespace is trimmed once,
  but the untouched trimmed spelling—including any query bytes—is hashed through
  `ResolveMCPServerIdentity("http", input)` and must equal the witness server ID.
  Only absolute HTTP(S) URLs with valid authority/hostname and no userinfo or
  fragment are accepted. The clear endpoint is never stored in witness v2.
- **Query handling is defense-in-depth, not universal detection.** Fixed
  known-sensitive decoded keys and decoded values exactly equal to the supplied
  campaign credential are rejected. Other arbitrary query bytes remain accepted
  identity input; AgentHound does **not** claim they are non-secret. Every accepted
  query is omitted from reports, witnesses, evidence, graph properties, errors,
  and logs.
- **Exact-origin forwarding.** Credential headers are attached only when
  lowercased scheme + hostname + effective port matches the original endpoint.
  Path/query do not affect origin; scheme downgrade, host/port change, malformed
  authority, or missing authority fails closed on every redirect request.
- **Typed denial and bounded close.** Only an actually observed typed HTTP
  `401`/`403` is a definitive auth denial; target-controlled text and JSON-RPC
  auth-like messages remain indeterminate. The MCP SDK's exact-endpoint close
  `DELETE` inherits the original absolute scenario deadline and is counted even
  when it times out. No blanket client timeout is applied to SSE.
- **Read-only.** The `cred-reach` scenario issues `resources/read` for the exact
  predicted resource only (unauth control + authed probe). It mutates nothing, so
  it needs no receipts or rollback.
- **Anonymous access is a fact, not a finding.** When the resource reads
  successfully without a credential the runner emits `PUBLIC_ACCESS_OBSERVED`
  (a raw fact). Findings derive only from composite edges, so this never
  auto-creates a finding; treat it as a policy concern only where authentication
  was expected.
- **Exact per-agent witness contract.** Witness v2 names one source
  `AgentInstance`, is exported only for HTTP-backed resources, and carries the
  actual ordered current `CAN_REACH` evidence node IDs with normalized concrete
  kinds. Promotion recomputes the unkeyed fingerprint and validates every
  identity/hash/kind/stage/outcome/topology field against current graph state.
  The positive publication revision is provenance only; equality is not proof or
  a promotion gate. The digest is a consistency checksum, not authenticity.
- **Prevalidation before canonical state.** Positive and negative campaign
  artifacts are checked immediately after generic ingest validation and before
  normalization, `BeginScan`, graph writes, or reconciliation. A rejection
  cannot overwrite evidence or retire coverage. Postgres retains only a random
  rejection ID plus bounded sanitized run/scenario/outcome/reason codes—never
  the artifact, witness, digest, endpoint, or secret.

### Campaign runner: reversible mutation round-trip

The `agenthound campaign --scenario mcp-poison-roundtrip` scenario is a STANDALONE
target-mutation validation. Unlike `cred-reach` it **mutates** the target (reusing
the `mcp.poison` module), so it inherits the destructive-primitive posture:

- **Both gates are required.** `--commit` is off by default and a mutating run
  requires the campaign acknowledgement plus the distinct poison/destructive
  acknowledgement. The optional admin `--auth-token` is used in process and is
  never copied to a report or receipt.
- **Never a blind write; receipts retained.** The mutation persists a receipt
  before the write. The inline cleanup uses the conflict-aware Revert: on a
  third-party change (conflict) or a failed re-read (indeterminate) it writes
  nothing and **retains** the receipt so `agenthound revert <engagement-id>` can
  retry it. Active cleanup is run-scoped, globally reverse-sequenced, bounded,
  non-cancellable, and fail-stop; engagement recovery is the intentionally
  different per-file-LIFO, continue-on-error fallback. Oracle and cleanup remain
  independent, and unsafe/unconfirmed cleanup emits its report before nonzero exit.
- **No-op rejection and frozen accounting.** `original == injected` is rejected
  before receipt persistence or target write and reports cleanup as
  `not_applicable`. Forward request/mutation/elapsed usage and exhaustion are
  frozen before separately timed cleanup begins.
- **Bounded, secret-free reporting.** Both fixed scenarios use the same versioned
  `RunReport`: fixed steps, sanitized target reference, per-step RFC3339Nano
  start/end timestamps, typed operation classes, applicable sanitized
  evidence/witness fingerprint, opaque receipt IDs, typed oracle/cleanup, and
  explicit actual HTTP-request/mutation/elapsed limits and usage. Redirect/retry
  dispatches count. Reports cannot carry receipt paths or hashes,
  request/response bodies, resource contents, target error text,
  original/injected mutation state, credentials, or auth tokens.
- **Protected immutable receipts.** Receipt directories/files are enforced at
  exactly `0700`/`0600`, including tightening existing permissive paths.
  Rollback-required original/injected mutation state is allowed only there.
  Receipts remain unchanged after success/failure; raw credentials/tokens are
  forbidden. Conflict-aware live-state checks enable partial retry, but completed
  stacked rollback replay is not promised universally idempotent.
- **Minimized config receipts.** Every new receipt has a random opaque ID.
  `mcp.config.implant` stores the target path plus only the servers key/name,
  canonical named-entry hash, and original file existence/mode required for
  safe reversion; it stores no injected JSON plaintext or whole-file hash.
  Protected legacy plaintext receipts still decode and use conflict-aware
  reversion.
- **Not an attack finding.** It emits no graph edge and makes no claim about a
  predicted credential path — the round-trip evidence stays in the campaign
  transport. It validates only that the mutation/rollback machinery works.

### A2A card evidence and key trust

A2A v1.0.1 signature verification separates cryptographic validity from identity trust. Operator-pinned JWKS keys produce `valid_trusted`. A key retrieved from a protected-header `jku` can produce only `valid_untrusted`: HTTPS authenticates the key host, not the claimed agent/provider. Inline `jwks` and top-level `jwks_uri` are recorded as nonstandard inactive evidence.

Remote `jku` requires HTTPS on the initial request and every redirect, validates the certificate identity even when `--insecure` is used for card retrieval, blocks link-local/metadata destinations, rejects fragments, and bounds redirects, bytes, key count, signatures, unique remote sources, and aggregate verification time. Invalid, expired, or explicitly revoked key evidence is rejected. Operators needing private/self-signed key infrastructure must pin the key locally with `--a2a-trusted-keys`; `--insecure` is not a bypass.

Card conformance and signature state qualify functional A2A edges. Invalid
cards are retained for visibility, but declarations alone do not create active
authentication identities or edges. A v1.0.1 empty security requirement is a
valid anonymous alternative under the protocol/OpenAPI model, so it remains
conformant and does not suppress a valid skill. Its `auth_method=none` evidence
is a declaration, not proof that a credential-free runtime request succeeded.
ProtoJSON null scope lists are empty scopes; optional skill repeated fields are
absent/null or arrays of strings. Other shapes make the skill nonconformant and
prevent it from emitting a functional `ADVERTISES_SKILL` edge.
An absent, null, or empty `signatures` field is unsigned and remains eligible
for the unsigned-card finding. A null optional unprotected signature header is
absent; non-null wrong-shaped signature fields remain malformed.

### `openwebui.loot` authenticated mode

`agenthound loot --type openwebui --api-key <key>` reads an
**operator-supplied** Open WebUI admin API key (or session JWT) and uses
it to enumerate the upstream provider keys an admin has configured
(`GET /openai/config`). Properties of this path:

- **Read-only by contract.** The Looter issues GET requests only — it
  reads `/api/config` (anonymous posture) and `/openai/config`
  (authenticated). It never touches Open WebUI's `POST
  /openai/config/update` mutator; that would be a Poisoner-class
  operation. A `get_only` regression test asserts the looter has no
  non-GET call site.
- **value_hash redaction.** Each emitted upstream Credential carries a
  SHA-256 `value_hash` (always populated, the cross-collector merge
  primitive). The raw upstream key is **omitted by default** and only
  stored on the node when `--include-credential-values` is set — same
  gating as the Config Collector and LiteLLM Looter.
- **Operator-key hygiene.** The supplied `--api-key` is never written to
  the scan output and appears only as an 8-char prefix in slog. The
  anonymous posture mode (no `--api-key`) emits no credentials at all.
- Ollama URLs read from Open WebUI admin configuration are marked configured
  references. They do not assert backend availability or anonymous auth until
  a direct Ollama probe verifies the same endpoint ID.

Output files are written via atomic `temp+rename` and chmod'd to
`0o600` on POSIX. **NTFS does not honor POSIX permission bits.** On
Windows, the output file inherits the directory's NTFS ACL, which
typically allows any local user to read it. Treat any AgentHound
output stored on Windows as readable by every local user account.

## TLS

- All HTTP transports verify certificates by default.
- `--insecure` disables certificate verification. Use only against
  self-signed targets in an authorized assessment, never as a default.
- `--insecure` applies only to the selected collection target. A
  card-controlled A2A `jku` always requires HTTPS with certificate and server
  identity validation. Operators assessing internal/self-signed issuers must
  pin their keys with `--a2a-trusted-keys` instead.
- A regression test in `modules/{mcp,a2a}/*_test.go` asserts strict
  default verification — a code change that silently weakens this
  fails CI.

## Supply chain

- **GitHub Actions are SHA-pinned.** Major-tag references are not
  used. Updates flow through Dependabot in `.github/dependabot.yml`.
- **govulncheck runs on every PR** (blocking). Stdlib vulns are
  patched by the Go toolchain version pinned in `go.mod`.
- **Go module licenses are checked** against an allow-list
  (`Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0,
  Unlicense, Zlib`). Adding a copyleft dep fails CI.
- **Releases are cosign-signed.** `checksums.txt` is signed via
  keyless OIDC; the signature gates every artifact in the release
  via the checksum chain.
- **SBOMs are published per archive.** Syft generates SPDX-JSON
  attached to each release.
- **Verify install** with the cosign one-liner shown in
  `install.sh`'s output when cosign is not on the operator's PATH.

## OPSEC reminders for operators

- The binary's name and contents are a known fingerprint. Renaming
  the binary removes one signal; the import table and the
  `agenthound-ingest` JSON it emits are not stealth.
- Atomic writes mean a SIGINT mid-scan does not leave a half-written
  scan file at the destination — but a temp file in the destination
  directory may briefly exist. The scan filename pattern is
  `.agenthound-*.json` during the write window.
- The collector logs to stderr. Use `--quiet` to suppress everything
  except errors, or `--log-json` to capture structured logs to a
  file for later review.
- Default install path is `$HOME/.local/bin`. Override with
  `AGENTHOUND_INSTALL_DIR=/path` if you need a different location.
  The installer never uses `sudo` and never writes outside of
  `$AGENTHOUND_INSTALL_DIR`.

## Reporting vulnerabilities

See `SECURITY.md` for the disclosure process.

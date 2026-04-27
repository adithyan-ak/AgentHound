# AgentHound — security model and threat-model commitments

## What AgentHound is

AgentHound is a transparent, authorized-assessment tool for AI agent
infrastructure. It enumerates configuration, queries documented
endpoints, and builds a graph of trust relationships. Operators run it
against systems they have been authorized to assess.

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

## Localhost token on mutating endpoints

Although the server is single-user, the operator's *browser* is not.
A malicious tab open in the same browser session can issue same-origin
POSTs to `127.0.0.1:8080` and run arbitrary Cypher or upload
attacker-chosen ingest data. To shut that drive-by path:

- The server generates a random 32-byte token at first startup and
  persists it to `~/.agenthound/server.token` with `0o600` perms.
  Override the path via `AGENTHOUND_TOKEN_PATH`. If `XDG_CONFIG_HOME`
  is set, the default becomes
  `$XDG_CONFIG_HOME/agenthound/server.token`. The token is reused on
  subsequent restarts (idempotent).
- All mutating HTTP routes require
  `Authorization: Bearer <token>`. Specifically: `POST /ingest`,
  `POST /query`, `POST /scans`, `DELETE /scans/{id}`, and the three
  `POST /analysis/*-path` endpoints.
- Read endpoints (graph reads, findings, prebuilt queries, rules,
  health, docs) stay open. Localhost-only reads on a single-user box
  are fine; gating them would force the UI to plumb auth through
  every TanStack Query call for no security gain.
- `GET /api/v1/auth/local-token` returns the token to same-origin
  callers. The embedded UI fetches it once on first load and caches
  it in memory. Same-origin enforcement is provided by CORS:
  `AllowCredentials: false` and `AllowedOrigins` is the
  operator-set allowlist (default `http://localhost:8080`), so a
  third-party tab cannot use a credentialed fetch to read the
  response.
- `agenthound-server` CLI subcommands (`ingest`, `query`) call the
  pipeline / reader directly and do **not** speak HTTP, so they
  bypass the token entirely. No CLI plumbing changes are required.

To revoke the token (e.g. you suspect another user on the box read
the file), delete `~/.agenthound/server.token` and restart the
server. The next startup generates a fresh token; any open UI tab
will need a refresh to re-fetch.

## Collector network behaviour

The collector makes outbound network calls to:

1. **Targets specified by the operator** — `--target`, `--targets`,
   `--config`, `--url`, or paths discovered by `--discover`.
2. **No one else.** No telemetry, no phone-home, no version-check
   pings, no crash reporting, and no upload to a central server.

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

Output files are written via atomic `temp+rename` and chmod'd to
`0o600` on POSIX. **NTFS does not honor POSIX permission bits.** On
Windows, the output file inherits the directory's NTFS ACL, which
typically allows any local user to read it. Treat any AgentHound
output stored on Windows as readable by every local user account.

## TLS

- All HTTP transports verify certificates by default.
- `--insecure` disables certificate verification. Use only against
  self-signed targets in an authorized assessment, never as a default.
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

# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in AgentHound, please report it responsibly through [GitHub Security Advisories](https://github.com/adithyan-ak/agenthound/security/advisories/new).

**Do not** open a public GitHub issue for security vulnerabilities.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix timeline:** depends on severity, typically within 30 days for critical issues

### Scope

The following are in scope:

- Authentication and authorization bypasses
- Injection vulnerabilities (Cypher injection, command injection)
- Data exposure (credentials, tokens, PII leaking through API responses or logs)
- Supply chain issues in AgentHound's own dependencies
- Container escape or privilege escalation in the Docker deployment

The following are out of scope:

- Vulnerabilities in MCP servers or A2A agents that AgentHound scans (report those to their respective maintainers)
- Denial of service through intentionally large graph data (the tool is designed for trusted operator use)
- Issues requiring physical access to the host

## Security design

AgentHound handles sensitive data (credentials, infrastructure topology, attack paths). Key security measures:

- **Credential hashing:** Config Collector hashes credential values by default (SHA-256). Raw values require explicit `--include-credential-values` flag.
- **Single-user posture:** `agenthound-server` binds to `127.0.0.1:8080` by default and has no application-layer auth. Remote access is the operator's responsibility (SSH tunnel, WireGuard, Tailscale, mTLS reverse proxy).
- **Localhost token on mutating endpoints:** the server generates a 32-byte token at startup, persisted at `~/.agenthound/server.token` (or `$AGENTHOUND_TOKEN_PATH`). All mutating HTTP routes require `Authorization: Bearer <token>`. The embedded UI fetches it transparently from `GET /api/v1/auth/local-token`. CLI tools (`agenthound-server ingest`, `query`) bypass HTTP entirely.
- **CORS:** `AllowCredentials: false`. The server has no credentials to send; this prevents drive-by browser attackers from riding ambient context to read the token endpoint.
- **Input validation:** All API inputs are validated. The `/query` endpoint requires the localhost token; node/edge kinds are checked against an allowlist before being interpolated into Cypher.
- **Container security:** Non-root user, minimal base image, no unnecessary packages.

For the full threat model see [`docs/security.md`](docs/security.md).

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

# Security policy

## Report a vulnerability

Report AgentHound vulnerabilities through [GitHub Security Advisories](https://github.com/adithyan-ak/agenthound/security/advisories/new). Do not open a public issue for an undisclosed vulnerability.

Include:

- a clear description and affected component;
- reproduction steps or a minimal proof;
- expected impact and required preconditions;
- the collector and server versions;
- a suggested fix when available.

The project aims to acknowledge reports within 48 hours, provide an initial assessment within seven days, and prioritize a fix based on severity and exploitability.

## Scope

In scope:

- command, Cypher, or request injection in AgentHound;
- unintended data exposure outside the documented single-operator boundary;
- bypass of AgentHound's contact policy, OriginGuard, ingest validation, or storage binding;
- supply-chain vulnerabilities in AgentHound dependencies;
- container escape or privilege escalation in the shipped deployment.

Report vulnerabilities in scanned MCP, A2A, or AI services to their maintainers. Resource exhaustion from intentionally adversarial graph volume is evaluated against the documented trusted-operator and bounded-input assumptions.

## Current security design

- The collector intentionally writes exact observed credentials and collected content to a plain JSON artifact. Treat it as sensitive offensive evidence.
- The server binds to loopback and has no application login. Remote deployments need an independent access boundary.
- OriginGuard checks browser origins on mutating routes; CORS does not allow credentials.
- Ingest validates node and edge kinds, identities, proof structure, coverage, and canonical property names before graph mutation.
- PostgreSQL and Neo4j share a binding marker and operate as one storage pair.
- Shipped containers run as non-root users on minimal base images.

See [Security and OPSEC](docs/operator/security.md) for operator guidance.

## Supported release

Security updates target the AgentHound 1.1 release line.

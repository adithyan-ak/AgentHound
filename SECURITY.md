# Security policy

AgentHound welcomes reports that help protect its users, their assessment data, and the systems they are authorized to assess. Please report suspected vulnerabilities privately so maintainers can investigate, fix, and coordinate disclosure responsibly.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest stable release in the `1.1.x` line | Yes |
| Current `main` branch | Yes |
| Prerelease, development, and older releases | No |

If an issue affects an unsupported version, please still report it if you can reproduce it on a supported version or believe it materially affects users of the current release.

## Report a vulnerability privately

Use GitHub's private vulnerability-reporting form for this repository:

1. Open [Security Advisories](https://github.com/adithyan-ak/AgentHound/security/advisories).
2. Select **Report a vulnerability**.
3. Submit the report through the GitHub Security Advisory (GHSA) form.

Do **not** open a public GitHub issue, pull request, Discussion, or social-media post for an undisclosed vulnerability. Do not include real credentials, bearer tokens, access codes, raw scan artifacts, collected third-party content, personal data, or production-system data in a report. Redact sensitive material and provide a minimal proof of concept whenever possible.

A private report should include:

- A clear description of the issue and the affected AgentHound component, distribution, or workflow.
- Reproduction steps and a minimal proof of concept.
- Expected impact, required preconditions, and affected collector and server versions.
- Relevant configuration, logs, request/response evidence, or screenshots with sensitive data removed.
- A suggested mitigation or fix, if available.
- Whether and how you would like to be credited if an advisory is published.

## Scope

### In scope

- Command, Cypher, request, template, or artifact injection in AgentHound.
- Exposure of secrets, raw scan artifacts, collected content, or sensitive metadata outside documented operator-controlled surfaces.
- Bypass of AgentHound's contact policy, OriginGuard, ingest validation, storage binding, recovery controls, or access-boundary assumptions.
- Credential leakage or unsafe credential handling in the collector, server, release assets, installer, published containers, Homebrew formula, or project-controlled CI/CD workflows.
- Supply-chain vulnerabilities in AgentHound dependencies when they affect a supported AgentHound release.
- Container escape, unintended privilege escalation, unsafe default exposure, or unauthorized remote access in shipped deployment assets.

### Out of scope

- Vulnerabilities in systems scanned by AgentHound, including MCP, A2A, model, notebook, gateway, vector-store, or other AI services, when the issue is not caused by AgentHound itself. Report those to the affected service's maintainer.
- Findings that depend on deliberately running AgentHound against systems, accounts, data, or networks you do not own or lack explicit authorization to test.
- Resource exhaustion from intentionally adversarial graph volume when it remains within documented trusted-operator and bounded-input assumptions.
- Social engineering, physical attacks, or vulnerabilities in unrelated third-party infrastructure.

## Good-faith research

We support good-faith research on AgentHound copies, releases, accounts, data, and infrastructure that you own or are explicitly authorized to test. To the extent permitted by applicable law, we consider research that follows this policy to be authorized.

Please:

- Avoid privacy violations, service disruption, and destruction or modification of data.
- Stop testing and report promptly if you encounter data that is not yours.
- Use an exploit only as far as needed to demonstrate the vulnerability.
- Use synthetic credentials, services, and test data wherever possible.
- Give maintainers a reasonable opportunity to investigate and remediate before public disclosure.

The following are not authorized under this policy:

- Denial-of-service, load, or stress testing that could impair users or services.
- Scanning, validating credentials against, or modifying systems outside an authorized test environment.
- Accessing, exfiltrating, modifying, deleting, or retaining data that is not yours.
- Establishing persistence, escalating access beyond what is needed for a minimal proof of concept, or pivoting to other systems.
- Automated high-volume testing or scanning against project infrastructure without prior written permission.

## What to expect

For reports submitted through the private GHSA form, maintainers aim to:

- Acknowledge receipt within **48 hours**.
- Provide an initial assessment within **7 days**.
- Share material status updates at least every **14 days** while remediation is active, when contact information is available.
- Coordinate public disclosure after a fix or effective mitigation is available, normally through a GitHub Security Advisory and release notes.

Resolution timelines depend on severity, reproducibility, affected users, and availability of a safe fix. Please do not publish exploit details or disclose the issue publicly while coordinated remediation is in progress.

## Recognition and rewards

AgentHound does not operate a bug-bounty program and does not offer monetary rewards for vulnerability reports. With your permission, maintainers may credit you in a published security advisory or release notes.

## Current security design

- The collector intentionally writes exact observed credentials and collected content to a plain JSON artifact. Treat it as sensitive offensive evidence.
- The server binds to loopback and has no application login. Remote deployments need an independent authenticated access boundary.
- OriginGuard checks browser origins on mutating routes; CORS does not allow credentials.
- Ingest validates node and edge kinds, identities, proof structure, coverage, and canonical property names before graph mutation.
- PostgreSQL and Neo4j share a binding marker and operate as one storage pair.
- Shipped containers run as non-root users on minimal base images.

See [Security and OPSEC](docs/operator/security.md) for operator guidance.

## Policy updates

This policy may be updated as AgentHound's security processes and supported release channels evolve.

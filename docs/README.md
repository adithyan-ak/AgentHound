# AgentHound documentation

AgentHound performs autonomous offensive collection and access verification against AI agent infrastructure. The collector writes one local JSON artifact; the optional server turns that artifact into full-graph paths, findings, risk, and an inspection dashboard.

## Start here

1. [Install AgentHound](getting-started/install.md).
2. Follow the [Quickstart](getting-started/quickstart.md) for your first scan and ingest.
3. Use the [Scanner guide](operator/scanner.md) for targets, modes, credentials, actions, and recovery.

## Operate and analyze

- [Attack paths](operator/attack-paths.md) explains inferred and scan-verified reachability.
- [Deployment](operator/deployment.md) covers the optional analysis stack.
- [Security and OPSEC](operator/security.md) describes active behavior and artifact handling.
- [CLI reference](reference/cli.md) lists every command and flag.

## Extend AgentHound

- [System design](architecture/system-design.md)
- [Server analysis](architecture/server-analysis.md)
- [Development setup](contributing/dev-setup.md)
- [Writing modules](contributing/modules.md)
- [Authoring rules](contributing/authoring-rules.md)

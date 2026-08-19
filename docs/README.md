# AgentHound Documentation

AgentHound is an autonomous offensive collector for AI agent infrastructure. One `scan` performs local collection, network discovery, service enumeration, compatible credential reuse, bounded access proof, immediate mutation cleanup, and continuous checkpointing to one plain JSON artifact.

The collector is fully operational without the server. Manually ingest the artifact later when full-graph analysis and dashboard inspection are useful.

## Start here

- [Install](getting-started/install.md)
- [Quickstart](getting-started/quickstart.md)
- [Scanner guide](operator/scanner.md)
- [CLI reference](reference/cli.md)
- [Security and operational behavior](operator/security.md)

## Analysis

- [Attack paths](operator/attack-paths.md)
- [Graph model](reference/graph-model.md)
- [Risk scoring](reference/risk-scoring.md)
- [Detection rules](reference/detection-rules.md)
- [API](reference/api.md)

## Architecture and contribution

- [System design](architecture/system-design.md)
- [Ingest pipeline](architecture/ingest-pipeline.md)
- [Post-processors](architecture/post-processors.md)
- [Writing modules](contributing/modules.md)
- [Development setup](contributing/dev-setup.md)
- [Two-binary decision](adr/0001-two-binary-split.md)

AgentHound has no separate discovery, loot, campaign, witness, extract, poison, implant, or collector-side ingest workflow. Those old operator decisions have been folded into `scan` or removed.

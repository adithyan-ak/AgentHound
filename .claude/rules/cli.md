---
paths:
  - "collector/cli/**"
---
# CLI Development Rules

- Persistent flags on rootCmd: --log-level, --output, --concurrency, --host-id, --network-realm-id, --quiet, --log-json, --rules-bundle
- Each lifecycle command has its own file: scan.go, discover.go, loot.go, poison.go, implant.go, revert.go, extract.go, campaign.go
- Mutating verbs (poison, implant) use the poison AUTHORIZED prompt + sentinel and --commit=false default. Extract has its own acknowledgement, runs local analysis in dry-run, and uses --commit only to emit ingest. Campaign has a distinct acknowledgement; mutation scenarios additionally require poison consent.
- FlagsModule dispatch: loot/poison/implant/extract init() calls module.ListByAction + RegisterFlagsFor
- collectModuleExtras(cmd, mod) introspects per-module flags and populates Extras map
- Output resolution: command --scan-output > resolved cfg.Output (root --output, then AGENTHOUND_OUTPUT) > auto-name
- Cobra state pollution: never use rootCmd.Execute() in tests with shared state; call RunE directly

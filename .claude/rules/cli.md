---
paths:
  - "collector/cli/**"
---
# CLI Development Rules

- Persistent flags on rootCmd: --log-level, --output, --concurrency, --quiet, --log-json, --rules-bundle
- Each verb has its own file: scan.go, discover.go, loot.go, poison.go, implant.go, revert.go, extract.go
- Destructive verbs (poison, implant, extract) use AUTHORIZED prompt + sentinel file + --commit=false default
- FlagsModule dispatch: loot/poison/implant/extract init() calls module.ListByAction + RegisterFlagsFor
- collectModuleExtras(cmd, mod) introspects per-module flags and populates Extras map
- Output resolution: --scan-output flag > root --output flag > cfg.Output > env AGENTHOUND_OUTPUT > auto-name
- Cobra state pollution: never use rootCmd.Execute() in tests with shared state; call RunE directly

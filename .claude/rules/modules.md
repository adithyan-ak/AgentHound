---
paths:
  - "modules/**"
  - "collector/cmd/agenthound/main.go"
---
# Module Development Rules

- Every module self-registers via init() in register.go
- Module ID format: dotted lowercase (e.g., "ollama.fingerprint", "mcp.poison")
- Action interfaces: Fingerprinter, Looter, Poisoner, Implanter, Extractor (in sdk/action/)
- Sidecar interfaces: FlagsModule (per-module CLI flags), StatefulModule (receipt persistence)
- Looters are GET-only by contract — mutating methods are Poisoners
- Poisoners MUST embed Reverter (compile-time enforced)
- Receipt persistence BEFORE mutation (safety gate 4)
- Disabled-fingerprinter fallback pattern: if rule fails to load, register a no-op stub
- Clone modules/ollamafp/ as the simplest fingerprinter reference
- Clone modules/mcppoison/ as the Poisoner+Reverter reference

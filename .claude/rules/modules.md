---
paths:
  - "modules/**"
  - "collector/cmd/agenthound/main.go"
---
# Module Development Rules

- Action modules self-register with sdk/module via init() in register.go. credreach/mcproundtrip use sdk/campaign; protoscan is an engine; config/mcp/a2a are legacy-collector compatibility registrations and do not implement Enumerator.
- Module ID format: dotted lowercase (e.g., "ollama.fingerprint", "mcp.poison")
- Action interfaces: Fingerprinter, Looter, Poisoner, Implanter, Extractor (in sdk/action/)
- Sidecar interfaces: FlagsModule (per-module CLI flags), StatefulModule (receipt persistence)
- Looters make no durable target mutation. GET/HEAD is the norm; documented idempotent lookup/search POSTs require get_only coverage. Mutating methods belong in Poisoners.
- Poisoners MUST embed Reverter (compile-time enforced)
- Receipt persistence BEFORE mutation (safety gate 4)
- Disabled-fingerprinter fallback pattern: if rule fails to load, register a no-op stub
- Clone modules/ollamafp/ as the simplest fingerprinter reference
- Clone modules/mcppoison/ as the Poisoner+Reverter reference

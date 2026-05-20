---
paths:
  - "**/*_test.go"
---
# Testing Rules

- Use httptest.NewServer for fingerprinter/looter/poisoner tests
- DB-dependent tests gate with: if os.Getenv("AGENTHOUND_NEO4J_URI") == "" { t.Skip() }
- Use t.TempDir() for state directories; t.Setenv("AGENTHOUND_STATE_DIR", tmp) for receipt tests
- Use t.Setenv("HOME", tmp) to bypass AUTHORIZED sentinel prompts in CLI tests
- Sentinel files to pre-create: loot-acknowledged, poison-acknowledged, extract-acknowledged
- Fingerprinter tests: happy path + negative (wrong response shape) + network error (closed port)
- Module tests MUST NOT use rootCmd.Execute() due to cobra state pollution — call RunE directly
- Race detector: always run with -race flag locally and in CI
- Coverage floor: 55% for unit tests (-short), 60% for full suite (with DBs)

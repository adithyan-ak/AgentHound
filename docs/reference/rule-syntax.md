# Rule Syntax Reference

AgentHound ships two rule types: **detection rules** (text-field matching against collected graph properties) and **fingerprint rules** (HTTP probe sequences for AI-service identification). Both are YAML and live under `sdk/rules/builtin/`.

---

## Detection Rules

Location: `sdk/rules/builtin/*.yaml`

### Schema

```yaml
id: "rule-id-kebab-case"          # 3-64 chars, [a-z0-9-]
name: "Human-Readable Name"
description: "What this rule detects and why it matters."
version: 1                         # Monotonic; bump on logic changes
enabled: true
severity: critical|high|medium|low|info
owasp: ["MCP01", "ASI03"]         # OWASP MCP Top 10 and/or Agentic Top 10 IDs
tags: ["supply-chain", "injection"]

scope:
  collector: mcp|a2a|config|all    # Which collector's output to scan
  targets:                         # Node property fields to evaluate
    - description
    - name

matcher:
  type: keyword|prefix|regex|entropy|compound
  # Type-specific fields below

emit:
  finding_type: "poisoned_description"
  property_key: "has_injection_patterns"    # Optional: set on matched node
  property_value: true                      # Optional: value to set
  labels: ["Suspicious"]                    # Optional: additional labels

tests:                             # Unit tests (not shipped in binary)
  - input: "ignore previous instructions"
    should_match: true
    description: "imperative override"
  - input: "list all files in /tmp"
    should_match: false
    description: "benign file operation"
```

### Matcher Types

#### `keyword`

Matches if any keyword appears in the target text. Use `match_mode: all` to require every keyword.

```yaml
matcher:
  type: keyword
  keywords: ["ignore previous", "disregard", "new instructions"]
  case_insensitive: true
  match_mode: any|all              # Default: any
```

#### `prefix`

Matches if the target text starts with any listed prefix.

```yaml
matcher:
  type: prefix
  prefixes: ["sk-", "ghp_", "AKIA"]
  case_insensitive: false
```

#### `regex`

Matches if the pattern finds at least one hit.

```yaml
matcher:
  type: regex
  pattern: "https?://[^\\s]+\\.(sh|ps1)\\b"
  case_insensitive: true           # Prepends (?i) if not already present
```

#### `entropy`

Matches high-entropy strings (credential detection).

```yaml
matcher:
  type: entropy
  charset: base64|hex
  threshold: 4.5                   # Shannon entropy bits
  min_length: 20                   # Skip short strings
```

#### `compound`

Boolean combination of child matchers.

```yaml
matcher:
  type: compound
  operator: and|or                 # Default: or
  matchers:
    - type: keyword
      keywords: ["exec", "spawn"]
    - type: regex
      pattern: "\\$\\{.*\\}"
```

---

## Fingerprint Rules

Location: `sdk/rules/builtin/fingerprints/*.yaml`

Fingerprint rules describe HTTP probes that identify AI services on the network. They are evaluated by the scanner module, not by the text-matching engine.

### Schema

```yaml
id: "ollama-api"                   # 3-64 chars, [a-z0-9-]
name: "Ollama API"
description: "Identifies Ollama instances via /api/version endpoint."
version: 2                         # v0.2 fingerprint format
service_kind: OllamaInstance       # Node label for the primary kind

probes:
  - method: GET|HEAD               # v0.2 restricts to read-only methods
    path: /api/version
    headers:                       # Optional request headers
      Accept: application/json
    matchers:
      - type: http_status
        status_code: 200
      - type: json_path
        path: $.version
        exists: true
    captures:                      # Optional: extract values from response
      version: $.version

emit:
  node_kinds:
    - OllamaInstance               # Primary label (MERGE target)
    - AIService                    # Umbrella label (SET)
  properties:
    version: "{capture:version}"
    auth_method: "none"
    is_anonymous_loot: "true"
```

### Probe Execution

All probes in a rule execute sequentially. The rule matches only if **every probe succeeds** (all its matchers pass). Network errors and non-matching responses yield `matched=false` without raising an error.

Probes are limited to `GET` and `HEAD` methods (read-only contract). Response bodies are capped at 1 MiB.

### Fingerprint Matcher Types

#### `http_status`

```yaml
- type: http_status
  status_code: 200                 # Exact match
  # OR
  status_range: "2xx"              # Accepts: "2xx", "200-299", or single "200"
```

#### `http_header`

```yaml
- type: http_header
  name: Content-Type
  value: application/json          # Substring match
  case_insensitive: true
  # OR
  pattern: "ollama|Ollama"         # Regex match (overrides value)
```

#### `body_equals`

```yaml
- type: body_equals
  value: "OK"                      # Exact match after trimming trailing whitespace
```

#### `body_contains`

```yaml
- type: body_contains
  value: "litellm"
  case_insensitive: true
```

#### `body_regex`

```yaml
- type: body_regex
  pattern: "\"version\"\\s*:\\s*\"\\d+\\.\\d+"
```

#### `json_path`

Minimal JSONPath subset: `$`, `$.field`, `$.field.subfield`. No array indices or filters.

```yaml
- type: json_path
  path: $.version
  exists: true                     # Just check existence
  # OR
  equals: "0.1.0"                  # Exact string match
  # OR
  regex: "^\\d+\\.\\d+"           # Regex against stringified value
```

### Captures and Property Templates

Captures extract values from probe responses for use in emitted node properties:

```yaml
captures:
  version: $.version               # JSONPath expression
  model_count: $.models.length     # (future: not yet supported)
```

In `emit.properties`, use `{capture:NAME}` placeholders:

```yaml
emit:
  properties:
    version: "{capture:version}"
    endpoint: "{capture:endpoint}"
```

Unresolved placeholders are preserved as-is in the output (makes misnamed captures visible). Captures not referenced in the template still appear as properties automatically.

### Bundle Override

Operators can ship custom fingerprint rules via `--rules-bundle <path>`. Same-id rules from the bundle override the embedded set. The bundle must be a directory of YAML files or a `.tar.gz` archive. Verify cosign signature before use.

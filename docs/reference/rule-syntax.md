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
  targets:                         # Node.property fields to evaluate (must be qualified — see allowlist below)
    - tool.description
    - tool.name

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

### `scope.targets` allowlist

Every entry in `scope.targets` must be a qualified `<subject>.<field>` name from this fixed list (`sdk/rules/validate.go`); unknown targets fail rule load:

| Target | Subject |
|--------|---------|
| `tool.description`, `tool.name`, `tool.input_schema`, `tool.combined` | MCP tool |
| `skill.description` | A2A skill |
| `resource.uri` | MCP resource |
| `instruction.content` | Instruction file |
| `credential.name`, `credential.value` | Credential |
| `server.command`, `server.args`, `server.env_keys`, `server.env_values`, `server.instructions` | MCP server |

### Matcher Types

#### `keyword`

Matches if any keyword appears in the target text. Use `match_mode: all` to
require every keyword. Set `word_boundary: true` when a capability term must be
a complete token: word letters, digits, and `_` on either side prevent a match,
so `exec` does not match `execute_query` and `command` does not match
`command_reference`.

```yaml
matcher:
  type: keyword
  keywords: ["ignore previous", "disregard", "new instructions"]
  case_insensitive: true
  word_boundary: true              # Optional; default false
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
  operator: and|or                 # Required — omitting the field fails validation
  matchers:
    - type: keyword
      keywords: ["exec", "spawn"]
    - type: regex
      pattern: "\\$\\{.*\\}"
```

### Canonical instruction shadow eligibility

A custom detection rule opts into the config instruction canonical shadow pass
automatically — there is no flag. A rule is eligible when all three hold:

- `emit.finding_type` is `has_injection_patterns`;
- `scope.collector` is `config` or `all`;
- `scope.targets` includes `instruction.content`.

Eligibility is a per-rule property, not per-target: a rule that also targets
other fields (for example both `tool.description` and `instruction.content`)
is still eligible, and the shadow pass applies whenever it evaluates the
`config` collector's `instruction.content` field. The canonical transforms and
exclusions are the same frozen V1 set documented under
[Canonical instruction shadow](detection-rules.md#canonical-instruction-shadow).

### `RunTests` parity

`agenthound rules test` (and the builtin fixture guard) evaluate each inline
`tests:` input through the exact same code path used at scan time: the raw view
is matched first, and only when the rule is canonicalization-eligible and the
canonical text differs is the shadow pass consulted. A single test input is
evaluated once per rule regardless of how many `scope.targets` the rule
declares, so an eligible multi-target rule's positive fixtures pass on either
the raw or the shadow match, and its negative fixtures must fail on both.
Fixtures for eligible rules therefore lock the same raw-first ordering and
bounded-transform behavior that production scanning uses.

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
  value: "OK"                      # Exact match after strings.TrimSpace (both leading and trailing Unicode whitespace)
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

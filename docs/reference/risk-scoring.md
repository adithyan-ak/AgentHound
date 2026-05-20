# Risk Scoring

AgentHound computes risk scores at two levels: per-edge weights (used by Dijkstra shortest-path) and per-node composite scores (0-100, used for prioritization in findings and the dashboard).

---

## Edge Risk Weights

Lower weight = easier to exploit = attacker prefers this path.

| Edge Kind | Condition | Weight |
|-----------|-----------|--------|
| `TRUSTS_SERVER` | `auth_method = none` | 0.1 |
| `TRUSTS_SERVER` | `auth_method = apiKey` | 0.3 |
| `TRUSTS_SERVER` | `auth_method = bearer` | 0.5 |
| `TRUSTS_SERVER` | `auth_method = oauth` | 0.7 |
| `TRUSTS_SERVER` | `auth_method = mtls` | 0.9 |
| `DELEGATES_TO` | unauthenticated | 0.1 |
| `DELEGATES_TO` | authenticated | 0.5 |
| `PROVIDES_TOOL` | _(always)_ | 0.1 |
| `PROVIDES_RESOURCE` | _(always)_ | 0.2 |
| `PROVIDES_PROMPT` | _(always)_ | 0.1 |
| `HAS_ACCESS_TO` | _(always)_ | 0.2 |
| `CAN_EXECUTE` | _(always)_ | 0.1 |
| `SHADOWS` | _(always)_ | 0.4 |
| `CAN_IMPERSONATE` | _(always)_ | 0.6 |

Unknown edge kinds default to 0.5 (mid-range, conservative assumption).

---

## Node Risk Scores

Each node type uses a weighted formula over sub-scores. Each sub-score normalizes to 0-100; the final composite is `round(weighted_sum, 2)`.

### AgentInstance

```
score = 0.30 * credential + 0.25 * blast_radius + 0.20 * auth_posture
      + 0.15 * tool_surface + 0.10 * poisoning
```

| Component | Computation |
|-----------|-------------|
| `credential` | 100 if any trusted server has high-entropy or hardcoded credentials; 60 if credentials exist but are vault-referenced; 0 otherwise |
| `blast_radius` | `min(reachable_resource_count * 10, 100)` |
| `auth_posture` | `(1 - avg_trust_edge_weight) * 100` (weak auth = high score) |
| `tool_surface` | `min(trusted_tool_count * 5, 100)` |
| `poisoning` | 100 if any loaded instruction file is suspicious; 0 otherwise |

### MCPServer

```
score = 0.35 * auth_strength + 0.25 * tool_risk + 0.20 * exposure
      + 0.20 * credential_handling
```

| Component | Computation |
|-----------|-------------|
| `auth_strength` | none=100, apiKey=70, bearer=50, oauth=25, mtls=10 |
| `tool_risk` | max `capability_risk` across all provided tools |
| `exposure` | public host=100, private network=50, localhost=20, unknown=0 |
| `credential_handling` | 100 if high-entropy or hardcoded creds; 50 if any env vars; 0 otherwise |

### MCPTool

```
score = 0.30 * capability_class + 0.25 * poisoning + 0.25 * access_sensitivity
      + 0.20 * input_validation
```

| Component | Computation |
|-----------|-------------|
| `capability_class` | max risk from capability surface (see table below) |
| `poisoning` | 100 if injection patterns detected; 50 if cross-references; 0 otherwise |
| `access_sensitivity` | max sensitivity of reachable resources (critical=100, high=75, medium=50, low=25) |
| `input_validation` | 100 if no input schema defined; 0 if schema present |

### Capability Risk Map

| Capability | Risk |
|------------|------|
| `shell_access` | 100 |
| `code_execution` | 100 |
| `credential_access` | 90 |
| `database_access` | 80 |
| `file_write` | 70 |
| `network_outbound` | 60 |
| `email_send` | 50 |
| `file_read` | 40 |
| _(unknown)_ | 20 |

---

## Resource Sensitivity Classification

Applied automatically during MCP enumeration based on URI pattern matching:

| Pattern | Sensitivity |
|---------|-------------|
| `postgres://`, `mysql://`, `mongodb://` with `prod` in host/path | critical |
| `file:///etc/` | critical |
| `*.env`, `*.key`, `*.pem`, `*.p12` | critical |
| `redis://` with `prod` in host | critical |
| Database URIs without `prod` | high |
| `file:///` (general) | medium |
| All other URIs | low |

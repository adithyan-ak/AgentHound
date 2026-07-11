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

### A2AAgent

```
score = 0.30 * auth_strength + 0.30 * blast_radius + 0.25 * delegation_surface
      + 0.15 * impersonation
```

| Component | Computation |
|-----------|-------------|
| `auth_strength` | none=100, apiKey=70, bearer=50, oauth=25, mtls=10 |
| `blast_radius` | `min(reachable_mcp_resource_count * 10, 100)` |
| `delegation_surface` | `min(delegated_a2a_agent_count * 20, 100)` |
| `impersonation` | `min(can_impersonate_peer_count * 25, 100)` |

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
| `credential_handling` | `max(base, blast)` where `base` = 100 if high-entropy or hardcoded creds else 50 (when any env vars), and `blast` = `min(Credential.blast_radius * 10, 100)`; 0 if no env vars |

`Credential.blast_radius` (distinct agents that can reach a value_hash-merged secret) is materialized by the `cross_service_credential_chain` post-processor, so a widely-shared secret amplifies its server's credential-handling risk even when the secret itself is not high-entropy.

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

Applied automatically during MCP enumeration by the shipped detection rules under `sdk/rules/builtin/sensitivity-*.yaml`. Buckets are applied in the order critical → high → medium; anything unmatched falls through to `low`.

| Pattern | Sensitivity | Source rule |
|---------|-------------|-------------|
| `postgres://`, `postgresql://`, `mysql://`, `mongodb://` with `prod` in URI | critical | `sensitivity-critical.yaml` |
| `redis://` with `prod` in URI | critical | `sensitivity-critical.yaml` |
| `s3://`, `gs://` with `prod` in URI | critical | `sensitivity-critical.yaml` |
| `file:///etc/shadow`, `file:///etc/passwd`, `file:///root/…` | critical | `sensitivity-critical.yaml` |
| `file://…` ending in `.env`, `.key`, `.pem`, `.crt`, `.p12`, `.pfx`, `.jks` | critical | `sensitivity-critical.yaml` |
| Any URI containing `/credentials`, `/secrets`, or `/.ssh/` (case-insensitive) | critical | `sensitivity-critical.yaml` |
| `postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `redis://` (no `prod` required) | high | `sensitivity-high.yaml` |
| `file:///var/log/…` | high | `sensitivity-high.yaml` |
| `file://…` config with `secret`/`password` in the name (`.conf`/`.cfg`/`.ini`/`.yaml`/`.yml`/`.json`) | high | `sensitivity-high.yaml` |
| `file:///`, `file://localhost/`, `http://`, `https://`, `s3://`, `gs://` (any URI not already critical/high) | medium | `sensitivity-medium.yaml` |
| Anything else | low | (fallback) |

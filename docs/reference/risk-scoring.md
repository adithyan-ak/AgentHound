# Risk Scoring

AgentHound computes risk scores at two levels: per-edge weights (used by bounded weighted-path traversal) and per-node composite scores (0-100, used for prioritization in findings and the dashboard).

---

## Edge Risk Weights

Lower weight = easier to exploit = attacker prefers this path.

| Edge Kind | Condition | Weight |
|-----------|-----------|--------|
| `TRUSTS_SERVER` | `auth_method = none` with explicit `anonymous_probe_succeeded` evidence | 0.1 |
| `TRUSTS_SERVER` | `auth_method = basic` | 0.25 |
| `TRUSTS_SERVER` | `auth_method = apiKey` | 0.3 |
| `TRUSTS_SERVER` | `auth_method = bearer` | 0.5 |
| `TRUSTS_SERVER` | `auth_method = oauth` | 0.7 |
| `TRUSTS_SERVER` | `auth_method = oidc` | 0.75 |
| `TRUSTS_SERVER` | `auth_method = mtls` | 0.9 |
| `TRUSTS_SERVER` | `auth_method = unknown/custom` | 0.5 (ranking only; assessment incomplete) |
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

Every scored node also carries `risk_score_min`, `risk_score_max`,
`risk_assessment_complete`, and `risk_unknown_factors`. `risk_score` remains a
rankable conservative upper bound for prioritization. Unknown evidence therefore
does not become a precise zero or a precise auth weakness; the UI must display
the bound and missing factors.

### AgentInstance

```
score = 0.30 * credential + 0.25 * blast_radius + 0.20 * auth_risk
      + 0.15 * tool_surface + 0.10 * poisoning
```

| Component | Computation |
|-----------|-------------|
| `credential` | 100 if any trusted server has high-entropy or hardcoded credentials; 60 if credentials exist but are vault-referenced; 0 otherwise |
| `blast_radius` | `min(reachable_resource_count * 10, 100)` |
| `auth_risk` | `(1 - avg_trust_edge_weight) * 100` (weak auth = high score) |
| `tool_surface` | `min(trusted_tool_count * 5, 100)` |
| `poisoning` | 100 if any loaded instruction file is suspicious; 0 otherwise |

### A2AAgent

```
score = 0.30 * auth_strength + 0.30 * blast_radius + 0.25 * delegation_surface
      + 0.15 * impersonation
```

| Component | Computation |
|-----------|-------------|
| `auth_strength` | none=100 only with explicit anonymous-probe evidence; basic=85, apiKey=70, bearer=50, oauth=25, oidc=20, mtls=10; unknown/custom/unsupported-none have no numeric weakness |
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
| `auth_strength` | none=100 only with explicit anonymous-probe evidence; basic=85, apiKey=70, bearer=50, oauth=25, oidc=20, mtls=10; unknown/custom/unsupported-none have no numeric weakness |
| `tool_risk` | max `capability_risk` across all provided tools |
| `exposure` | public host=100, private network=50, localhost=20; unknown contributes a 0-100 bound and marks assessment incomplete |
| `credential_handling` | Observed/exposed material only: `max(base, blast)` where `base` = 100 if high-entropy or hardcoded creds else 50, and `blast` = `min(Credential.blast_radius * 10, 100)`. Masked, hashed, unobserved, and identity-only references do not count. |

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
| `access_sensitivity` | max sensitivity of reachable resources (critical=100, high=75, medium=50, low=25); unknown contributes a 0-100 component bound |
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

Applied automatically during MCP enumeration by the shipped detection rules under `sdk/rules/builtin/sensitivity-*.yaml`. Buckets are applied in the order critical → high → medium → low. An unmatched URI is `unknown` with `sensitivity_evidence=no_rule_match`; low requires positive rule evidence.

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
| Anything else | unknown | no matching rule |

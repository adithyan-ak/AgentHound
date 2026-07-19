# `agenthound poison` and `agenthound revert` — destructive primitives

> **Read this before you run anything in this document.** Poisoners modify on-target state. Even when reverted, the modification is in the target's audit trail (HTTP access log, file mtime, database WAL). Operating these primitives without written authorization for the target system violates the Computer Fraud and Abuse Act (US, 18 U.S.C. § 1030), the Computer Misuse Act 1990 (UK), § 202a–c (Germany), and equivalent statutes worldwide.

## What `poison` does

`agenthound poison <host> --type <kind> ...` rewrites a piece of state on the target — a tool description, an instruction file, a config-file entry — that an AI agent will consume. The change is the substrate of an attack: a poisoned tool description redirects an agent's planning step; a poisoned CLAUDE.md changes how the agent reasons across an entire project.

Every Poisoner module embeds the `Reverter` interface (`sdk/action/reverter.go`). The compile-time embedding means a Poisoner without a recovery implementation will not build. Every `Poison()` call returns a `PoisonReceipt` containing the rollback state; `agenthound revert` reads receipts off disk and invokes each module's Revert. This is an implementation guarantee, not a promise that an external provider will accept restoration after policy drift, conflicts, deletion, or loss of access. AgentHound reports and verifies the runtime outcome.

## Safety controls

Four gates, all on by default. Decision G in `docs/plans/v0.3-v0.4-implementation.md`:

| Gate | What it prevents | How to override |
|---|---|---|
| `Reverter` is mandatory at compile time | Destructive modules shipping without a recovery implementation | Cannot — refactor the module |
| `--commit=false` is the CLI default | Accidentally tampering during reconnaissance | Pass `--commit` only with authorization in hand |
| `~/.agenthound/poison-acknowledged` sentinel + AUTHORIZED prompt | First-run blank-stares-at-cli destructive actions | Type `AUTHORIZED` once; sentinel persists |
| Receipt persistence before "applied" success | Crash between HTTP write and receipt write | Cannot — design invariant |

## Receipt locations

```
~/.agenthound/state/<module-id>/<engagement-id>.json
```

- Receipt files are enforced at exactly `0o600`; receipt directories are enforced at exactly `0o700`. Existing permissive paths are explicitly tightened before reads/writes, and files are chmod'd after atomic replacement so umask cannot weaken the policy.
- One file per `(module-id, engagement-id)` tuple. Multiple receipts for the same engagement append to the same file as a JSON array.
- New receipts carry a random opaque `receipt_id` that is independent of target paths and receipt contents. Campaign reports link only this ID; they never expose receipt paths or receipt/content hashes.
- Receipts include `module_id`, `target`, `target_id`, the rollback state required by that module, `mode`, `applied_at`, and `dry_run`. Campaign mutations also carry `campaign_run_id` and a positive invocation-order `step_sequence`; `applied_at` is diagnostic only. ContextForge tool-description receipts additionally carry a typed, versioned provider contract with separate MCP and management identities, fixed paths/method/status, original and updated descriptions, the original ContextForge version, and precomputed forward/restore operation User-Agents.
- File-mutating modules record original file existence/mode so revert can restore the exact prior state. New `mcp.config.implant` receipts additionally store only the servers key, server name, and canonical implanted-entry SHA-256 for conflict detection—never the injected JSON plaintext or a whole-file hash. Legacy protected receipts containing plaintext `InjectionContent`, `file`, and `orig_mode` remain decodable and revertible.
- Override the state root with `AGENTHOUND_STATE_DIR` (used by tests; production should leave it alone).
- Receipts are the only permitted store for rollback-required original/injected mutation values. Raw credentials and auth tokens are forbidden even in receipts. ContextForge recovery resolves its MCP and management credentials again from environment/config sources; an untyped, unknown-version, or wrong-profile MCP receipt is rejected before networking.

### Restore fidelity

For modules that mutate on-disk files, `revert` restores the file's prior state precisely:

- **File that did not exist before** is **removed** on revert (not left behind as an empty shell), restoring the original absent state. If the operator or client added other content to that file after the mutation, revert keeps the file and only drops the agenthound-owned entry/block.
- **Pre-existing file** keeps its **original permission mode** — revert no longer narrows it to `0o600`. The mode captured at mutation time (`orig_mode`, or `original_mode` in minimized config receipts) is reapplied.
- Receipts written before these fields existed default to the prior conservative behavior (leave the file, mode `0o600`), so older receipts still revert safely.

## Shipped destructive modules

| `--type` | Verb(s) | Source → Target | Reverter behavior |
|---|---|---|---|
| `mcp.tool.description` | `poison` | ContextForge server-scoped `MCPServer` → `MCPTool.description` | Restore only an exact tool-UUID/version/User-Agent attribution; verify MCP when the association still exists, otherwise report verification unavailable. |
| `instruction.file` | `poison`, `implant` | operator machine → `CLAUDE.md` / `AGENTS.md` / `.cursorrules` | Rewrite the file to remove the sentinel-bracketed block; if the file did not exist before mutation (`file_existed=false` on the receipt), remove it entirely. Pre-existing files keep their original permission mode (`orig_mode`). |
| `mcp.config.malicious-server` | `implant` | operator machine → MCP client config (`.cursor/mcp.json` etc.) | Hash-compare the current named entry against the canonical entry hash, then remove only that entry; preserve unrelated edits and drop the file only when AgentHound created it and no unrelated content remains. Legacy plaintext receipts use the same conflict-aware fallback. |

`agenthound implant --type instruction.file` accepts the Poisoner-backed module too — the implant dispatcher falls back to the shared poison runner when no Implanter matches the requested target kind, so operators get consistent CLI ergonomics regardless of which contract the module implements.

## Worked example — MCP tool description

```bash
# 1. Optional management override. It is required when management is on a
#    different origin from MCP.
export AGENTHOUND_CONTEXTFORGE_TOKEN='...'

# Put the authorized direct-poison payload in payload.txt.

# 2. First-run AUTHORIZED prompt + sentinel. This is a dry-run: the adapter
#    performs bounded identity/preflight reads but issues no PUT.
echo "AUTHORIZED" | agenthound poison \
    https://gateway.example/servers/<server-uuid>/mcp \
    --type mcp.tool.description --adapter contextforge \
    --target-id support-lookup \
    --inject-file payload.txt \
    --engagement-id DC35-DEMO
#
# Output:
# [poison] DRY-RUN mcp.tool.description https://gateway.example/servers/<server-uuid>/mcp — engagement_id=DC35-DEMO
#          receipt=~/.agenthound/state/mcp.poison/DC35-DEMO.json
# [poison] re-run with --commit to apply.

# 3. With --commit, the actual mutation lands once.
agenthound poison https://gateway.example/servers/<server-uuid>/mcp \
    --type mcp.tool.description --adapter contextforge \
    --target-id support-lookup \
    --inject-file payload.txt \
    --commit \
    --engagement-id DC35-DEMO

# 4. Live agent now sees the poisoned description on its next tools/list.
#    Exercise the agent however your demo harness invokes it.

# 5. Revert. Keep the same credential sources available.
agenthound revert DC35-DEMO
#
# Walks every registered StatefulModule, reads receipts for DC35-DEMO,
# dispatches per-module Revert. Retries are conflict-aware; immutable stacked
# receipts are not universally replay-idempotent after a completed rollback.
```

## Per-module flags (`mcp.tool.description`)

```
--adapter contextforge                Required provider selection
--management-url <deployment-root>    Optional override when management is not rooted
                                      beside the server-scoped MCP URL; omit /v1
--insecure                            Skip TLS verification on both surfaces (default off)
```

There is no default or generic MCP management endpoint: MCP defines observation of tools, not a metadata-update method. The `contextforge` adapter is one narrow provider contract. It requires a positional MCP URL ending in `/servers/<server-uuid>/mcp`; an optional reverse-proxy prefix and trailing slash are accepted, while userinfo, query, fragment, malformed escapes, and other endpoint shapes are rejected. The server ID is copied from ContextForge v1.0.5 in its exact lowercase 32-hex wire form; hyphenated or encoded alternatives fail closed. Unless `--management-url` is supplied, AgentHound derives the deployment root by removing the server-scoped suffix. A management override is an absolute deployment base, not an API path; it must omit userinfo, query, fragment, and `/v1` because AgentHound appends the fixed API prefix itself.

The fixed management sequence is:

1. initialize an official MCP SDK session, exhaust bounded `tools/list` pagination, and observe exactly one `--target-id` name and description;
2. require a session token or empty/wildcard API-token permission ceiling, then prove effective `servers.read` in the server-team context and `tools.read`/`tools.update` in the tool-team context before reading `GET /v1/servers/<server-uuid>/tools` and `GET /v1/tools/<tool-uuid>` successfully;
3. require one associated row whose exact `name` and `description` match MCP, whose UUID, integer `version`, and `modifiedUserAgent` are unambiguous, and require a non-admin identity to be the direct `ownerEmail` of both the server and tool;
4. persist the typed receipt before mutation;
5. issue exactly one `PUT /v1/tools/<tool-uuid>` with the fixed body `{"description":"..."}` and require an exact `200` JSON object;
6. use bounded read-only polling until both ContextForge and MCP show the updated description. Polling never repeats the forward write.

Redirects, HTML/non-JSON bodies, oversized responses, unexpected statuses, duplicate identities, and mismatches fail closed. If the write response is lost, AgentHound reconciles with read-only observations and accepts forward success only when the next ContextForge state has exactly version `V+1`, the intended description, and the pre-recorded forward operation User-Agent. It never retries the forward PUT. If ContextForge instead lands a normalized value `C`, the forward result fails; inline cleanup may still restore `C` when the exact tool UUID, `V+1`, and forward User-Agent attribute that row to AgentHound. Failed MCP projection likewise triggers the one cleanup attempt, never another forward mutation.

Both the encoded forward and restoration description PUTs must fit the 256 KiB request cap before receipt persistence or any mutating write. AgentHound also measures the exact preflight `ToolRead` JSON and rejects the update unless both the original record and the projected forward response retain a fixed metadata margin inside the separate 1 MiB response bound. A row carrying an AgentHound forward-operation User-Agent is ineligible for another mutation, across all engagements, until recovery restores it. Within one engagement, an older same-row receipt also blocks a new mutation while its recorded original description is not live. These guards prevent request/response-bound recovery failures and version chains that immutable provider attribution cannot safely unwind; verified restoration permits reuse.

ContextForge v1.0.5 does not expose a non-mutating endpoint that proves an existing description will still pass the current `ToolUpdate` and content-security validators byte-for-byte. A row created under permissive validation can remain readable after the deployment enables stricter or different rules, while a later PUT of that same original text is rejected. AgentHound does not issue a hidden no-op PUT to test this because that request itself increments the row version and rewrites audit attribution. Consequently, validator-configuration drift can make restoration fail even when it happened before the engagement and the configuration remains stable during the run. This is a known provider limitation, separate from the read→write TOCTOU below; verify that the current deployment accepts the existing description before `--commit` when validation policy has changed.

The nested provider receipt is deliberately one schema only: `receipt_type=mcp_tool_description_contextforge`, `receipt_version=1`, `management_profile=contextforge`, and `contract_id=contextforge-v1-tool-description-put`. There is no fallback decoding for the removed generic MCP workflow.

### ContextForge credentials and authorization

- MCP authentication resolves from `AGENTHOUND_MCP_TOKEN` or one unique `Authorization` header attached to the exact positional URL in existing MCP client configs. AgentHound does not match by origin or normalized URL and does not infer stdio-wrapper or routing headers.
- `AGENTHOUND_CONTEXTFORGE_TOKEN` is an independent management override. When it is unset, same-origin management reuses the resolved MCP bearer; a cross-origin `--management-url` requires the explicit ContextForge token. Credentials are attached only to their allowed origins and never appear in receipts, reports, logs, or recovery output.
- AgentHound does not mint, discover, or elevate ContextForge management credentials. Obtain an authorized session/API bearer through the deployment's existing authentication or token workflow before the engagement.
- ContextForge v1.0.5 applies token permission claims as a Layer-1 ceiling and database RBAC as a separate Layer-2 decision. AgentHound therefore accepts a session token or an API token with an empty/wildcard permission ceiling and reads the fixed `/v1/auth/email/me` profile. For non-admins, it queries `/v1/rbac/my/permissions?team_id=<uuid>` for the exact server and tool team contexts; effective RBAC must provide `servers.read`, `tools.read`, and `tools.update`, so provision the account with only those roles. The identity must also match the direct `ownerEmail` of both objects; a JWT team-membership value is not proof of ContextForge's team-owner role and fails closed. A platform-admin bypass is accepted only from the provider-authenticated profile. Exact non-wildcard API-token ceilings are rejected because v1.0.5 blocks the preflight endpoints needed to prove authorization. Exact server/tool reads must also succeed. Missing, ambiguous, or contradictory evidence fails before mutation.
- `--insecure` is an explicit opt-out from certificate verification for authorized self-signed deployments. It applies to the direct poison, campaign round-trip, and `revert --insecure`; strict verification remains the default and origin binding still applies.
- ContextForge and any reverse proxy must preserve AgentHound's unique forward and restore operation User-Agents. Recovery cannot safely attribute a write if a proxy overwrites that header.

### Recovery ownership and residual race

ContextForge does not expose a conditional update primitive that this contract can use: there is no ETag/`If-Match` or compare-and-swap. AgentHound therefore records the exact tool UUID, original version/`modifiedUserAgent`, and unique forward/restore operation User-Agents. Revert may restore whatever description landed—including normalized `C`—only when that exact row remains at `V+1` with the forward User-Agent. The current description need not equal the outbound text. If normalization lands text equal to the original but leaves `V+1` and the forward User-Agent, revert still performs the restore transition; it is not treated as a completed no-op. A different UUID, version, or User-Agent is a conflict; a failed exact row read is indeterminate. Both outcomes issue no write.

Server/tool association drift does not block restoration of the exact attributed row. AgentHound reports MCP verification unavailable in that case instead of pretending the management row is still projected by the original MCP endpoint. When association remains intact, it verifies the original description through the official SDK. After its one restore PUT, management must show the original description, version `V+2`, and restore User-Agent. These checks are strong post-hoc ownership evidence, not atomic concurrency control. A third party can still write between AgentHound's final pre-write read and its unconditional PUT, so both forward mutation and restoration retain a read→write TOCTOU window that can overwrite a concurrent edit. Run this adapter only in an exclusive operation window. Strict conflict safety requires server-side CAS support that ContextForge does not currently provide.

For standalone recovery after proven association drift, `agenthound revert` reports `PARTIALLY VERIFIED`: the exact management row is restored and verified, while MCP verification is explicitly unavailable. An association-read error is not detachment proof; AgentHound requires full management/MCP cleanup verification and reports the result indeterminate when that cannot complete.

## Modes

```
--mode replace   InjectedContent overwrites OriginalContent
--mode append    OriginalContent + InjectedContent
--mode prepend   InjectedContent + OriginalContent
```

`replace` is the default. `append`/`prepend` preserve the original — useful when the agent needs the legitimate description AND the attacker's hidden instruction (the canonical "tool description with hidden footer" pattern).

## What `revert` does NOT do

- It does not delete the receipt files. They are the audit trail.
- It does not roll back any state on the target other than what `Poison` explicitly changed (no log scrubbing, no `mtime` manipulation, no SIEM evasion).
- It does not run on dry-run receipts (`dry_run: true`) — those never mutated anything.
- It does not work across machines. Receipts are local; `agenthound revert` only sees what was applied from THIS machine.
- It does not globally sequence a lost campaign run. Engagement recovery uses per-file LIFO and continues across independent module errors. Active run-scoped cleanup instead selects one exact campaign run, globally sorts by descending `step_sequence`, and fail-stops on the first unsafe dependent step.

## What `poison` does NOT do

- It does not detect EDR or audit logging on the target. Probes show up in HTTP access logs unconditionally.
- It does not anonymize the operator. `--engagement-id` is recorded on every emitted edge's evidence map for downstream IR coordination, NOT for evasion.
- It does not chain implants. Each Poisoner does one thing; persistence-installing modules run under the separate `agenthound implant` verb (see the shipped-modules table above and the [CLI reference](../reference/cli.md)).

## `agenthound extract` — read-only, gated

The `extract` verb is the third gated primitive alongside `poison` and `implant`. It runs a registered `Extractor` (`sdk/action/extractor.go`) against a local artifact, produces derived-signal graph data, and — like `poison` / `implant` — refuses to run without an operator-typed `AUTHORIZED` acknowledgement.

- **Shipped module:** `embedding-invert` (`modules/embeddinginvert/`). Detects fine-tune training signals via statistical outlier analysis of a GGUF model's embedding layer.
- **Gates:**
  - `--commit=false` by default — without it the Extractor runs end-to-end but emits a dry-run summary only, no ingest data.
  - `~/.agenthound/extract-acknowledged` sentinel + AUTHORIZED prompt on first run (separate sentinel from `poison-acknowledged`, since `extract` is billing/CPU-heavy rather than target-mutating).
  - `--artifact <path>` is required — Extractors operate only on local files the operator has already obtained out-of-band (e.g. GGUF blobs copied from `~/.ollama/models/blobs/`). AgentHound never downloads model weights on your behalf.
- **Output:** emits `ExtractedTrainingSignal` nodes linked to their source `AIModel` via `EXTRACTED_FROM` edges. The required source argument is the already-established canonical AgentHound node ID (`sha256:` plus 64 lowercase hexadecimal characters), not a URL or model name. The envelope carries that source as an empty `reference_only` endpoint, so it is strict-ingest-valid without claiming or replacing model properties.
- **Non-destructive:** the module returns `IsDestructive() = false`; it does not modify the on-disk artifact and does not embed the `Reverter` contract.

```bash
# Dry-run first.
agenthound extract <ai-model-node-id> \
    --type embedding-invert \
    --artifact /path/to/support-agent-v3.gguf \
    --engagement-id DC35-DEMO

# With --commit, emit ingest data.
agenthound extract <ai-model-node-id> \
    --type embedding-invert \
    --artifact /path/to/support-agent-v3.gguf \
    --commit \
    --engagement-id DC35-DEMO \
    --output -
```

## Campaign runner: verify and validate

`agenthound campaign <host> --scenario <id>` runs an ordered, evidence-producing scenario against a known service. Like `poison`/`extract` it is gated: `--commit` is off by default (dry-run plans only), and the first invocation prompts for `AUTHORIZED` (sentinel `~/.agenthound/campaign-acknowledged`). The runner ships two scenarios.

### `cred-reach` — read-only differential verification

Given an HTTP-only witness v2 for one explicit source agent's predicted credential-gated `CAN_REACH` finding, `cred-reach` binds the untouched trimmed endpoint spelling to the witness server ID before networking, then reads the exact resource without and with the hash-matched credential. Credentials are scoped to exact scheme+hostname+effective-port across redirects. A control initialization denial plus an authenticated exact resource read verifies; only dual exact resource-read denials can retire that agent's prior evidence. Other failures are indeterminate, while a successful anonymous control read remains an independent fact. It proves credential-gated resource reach associated with the source agent—not observed agent invocation or impact.

### `mcp-poison-roundtrip` — standalone target-mutation validation

`mcp-poison-roundtrip` reuses the ContextForge-specific `mcp.poison` module (Poison + the conflict-aware Revert above) to prove the reversible mutation machinery works end to end against a real target. It is a **validation of the round-trip**, not an attack: it does **not** create a finding and makes **no** claim about a predicted credential path. AgentHound generates a benign run-specific marker; the operator does not supply mutation text.

```bash
# Dry-run first (plans only — no mutation).
# Optional same-origin override; required for cross-origin management.
export AGENTHOUND_CONTEXTFORGE_TOKEN='...'
agenthound campaign https://gateway.example/servers/<server-uuid>/mcp \
    --scenario mcp-poison-roundtrip --adapter contextforge \
    --target-id support-lookup \
    --engagement-id DC35-DEMO

# With --commit: mutate -> re-read (ORACLE) -> conflict-aware revert -> re-read (CLEANUP).
agenthound campaign https://gateway.example/servers/<server-uuid>/mcp \
    --scenario mcp-poison-roundtrip --adapter contextforge \
    --target-id support-lookup \
    --engagement-id DC35-DEMO --commit
#
# Output (oracle and cleanup reported SEPARATELY):
# [campaign] COMMITTED mcp-poison-roundtrip on https://gateway.example/servers/<server-uuid>/mcp \
#            (STANDALONE target-mutation validation) — oracle=mutation_verified cleanup=restored
```

Behavior and safety:

- **Oracle and cleanup are independent.** The oracle (did the mutation land?) is decided from the post-mutation re-read; the cleanup (was the original restored?) is decided from the conflict-aware revert plus a post-revert re-read. A verified mutation with a failed cleanup (e.g. a third party edited the target mid-run) is reported honestly, never masked.
- **Provider identity is discovered, not typed.** The operator supplies the MCP tool name, not the ContextForge tool UUID. The adapter derives the server UUID from the MCP URL and accepts exactly one server-associated management row matching the SDK-observed name and description.
- **One generated forward write.** The round-trip uses an inert per-run marker, sends the forward PUT once, and polls read-only for propagation. A lost response is reconciled by version/User-Agent evidence; normalization or failed MCP projection produces a failed forward result and one inline cleanup, never another forward mutation. Cleanup can restore normalized landed text when the exact UUID/`V+1`/forward-User-Agent attribution matches.
- **Distinct consent and bounded execution.** `--commit` requires both the campaign acknowledgement and poison/destructive acknowledgement. The shared `RunReport` records per-step RFC3339Nano start/end timestamps, typed operation classes, sanitized evidence/witness fingerprints, opaque receipt IDs, and actual outbound HTTP requests, forward mutator invocations, and elapsed-time limits/usage. Budget exhaustion is unsafe/indeterminate; cleanup cannot change frozen forward accounting.
- **Authoritative run cleanup.** The run ID exists before mutator construction; each receipt gets one positive sequence immediately before invocation. Cleanup selects the exact engagement+run across all modules, rejects missing/duplicate metadata before writing, reverts globally newest-sequence first under a separate bounded non-cancellable context, and fail-stops. It then re-reads the target before reporting `restored`; unsafe cleanup emits the final report and exits nonzero.
- **Immutable receipts and fallback.** Successful and failed cleanup retain receipts unchanged. `agenthound revert <engagement>` remains the crash/state-loss fallback, with intentionally different per-file LIFO/best-effort behavior. ContextForge recovery accepts only its typed receipt version/profile.
- **No new graph edge.** Round-trip evidence stays in the bounded CLI `RunReport`; it is deliberately not emitted as a scored graph edge, finding, server execution API, or UI execution surface.
- Takes `--target-id` and `--adapter contextforge`, plus optional `--management-url` and `--insecure` — no witness, operator mutation text, or credential flag. See the [CLI reference](../reference/cli.md#agenthound-campaign) for the full flag table.

The campaign runner is deliberately two fixed local sequences. It has no DAG or
generic scheduler, server-side execution API, impact oracle, `ATTACK_PROVEN`
state, cleanup journal/state machine/CAS, or publication-revision equality gate.

The closure regression builds the real `agenthound` collector binary, exports a
production witness to a temporary file, exercises the real authorization/env/CLI
surface against an authenticated MCP stub, decodes the emitted artifact, and
passes it through the real ingest and processor-rebuild path. It asserts that
exactly one source-agent finding upgrades; adjacent real-pipeline cases preserve
canonical state for invalid positive/negative and tampered artifacts and keep
the second shared-path agent predicted.

## See also

- `docs/plans/v0.3-v0.4-implementation.md` — the destructive-action design rationale (decision G).
- `sdk/action/poisoner.go`, `sdk/action/reverter.go` — the contract.
- `sdk/module/stateful.go` — receipt persistence helper.
- `modules/mcppoison/` — the ContextForge provider implementation.
- [security.md](security.md) — full operator OPSEC guide.

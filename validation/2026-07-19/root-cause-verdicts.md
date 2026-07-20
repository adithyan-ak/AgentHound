# AgentHound v1.0 Independent Root-Cause Verdicts

## Decision

The validation candidate fixes ten independently demonstrated product root
causes. The documentation-contract group and the release-oracle group are also
confirmed. None of the twelve groups was rejected.

This does **not** mean that the ledger found 47 independent baseline bugs. The
47 numbered records divide into:

| Classification | Count | Issue numbers |
|---|---:|---|
| Baseline product-defect records | 35 | 1–9, 11, 13–16, 18, 21–33, 35–37, 40, 44–46 |
| Candidate-integration or hardening corrections | 7 | 10, 12, 19, 20, 41, 43, 47 |
| Documentation-only contract defects | 3 | 17, 34, 42 |
| Validation-oracle defects; product was not shown wrong | 2 | 38, 39 |
| **Total** | **47** | Every numbered ledger issue exactly once |

The 35 baseline product records are symptoms and boundary cases within ten
product root-cause groups. They must not be advertised as 35 independent root
causes. The seven integration corrections are valuable findings from testing
the candidate as a composed system, but they must not be presented as defects
that existed in the untouched baseline.

Stack construction later found two additional post-checkpoint composition
issues, S5-F1 and S5-F2. They are documented below but deliberately do not
change the frozen 47-record accounting above.

## Frozen comparison

- Untouched baseline: `1e45601c4d004247da60c0f0e796debfb3cc37fc`
- Candidate product checkpoint: `6428f13`
- Stack 05 corrective commit: `2232e05829313b05b772e84ca85254b65d4c6bd6`
- Validation-index checkpoint: `ed2ac62`
- Local branch: `codex/validation-snapshot-20260719`
- Detailed chronological evidence: `test-infra/artifacts/release-validation-working/ledger.md`
- Accepted final infrastructure run: `test-infra/artifacts/20260719T183642Z-73394`
- Independent evidence workspace: `/tmp/agenthound-rootcause-validation-20260719`
- Untouched baseline worktree: `/tmp/agenthound-validation-baseline-1e45601`
- Snapshot bundle: `/tmp/AgentHound-validation-snapshot-20260719.bundle`
- Snapshot bundle SHA-256: `f177294439517f8c55857a04c30cb137fa332e62e98b0f256ddd8bced7d1c0fd`

The configured `origin` is the public `adithyan-ak/AgentHound` repository. The
unreviewed snapshot was intentionally not pushed. The unrelated untracked
`AGENTS.md` file was excluded from the checkpoint and left untouched.

## Verdict matrix

| Root cause | Verdict | Baseline defect independently reproduced | Candidate behavior independently verified | Important qualification |
|---|---|---|---|---|
| RC-01 release-version provenance | CONFIRMED | Yes | Yes | One baseline artifact writer overrode the injected version. |
| RC-02 authentication/observation truth | CONFIRMED | Yes | Yes | Issue 43 is candidate hardening for the new A2A observer. |
| RC-03 protocol preservation/determinism/bounds | CONFIRMED | Yes | Yes | The three-minute timeout reproduction was stopped once; repeated hanging was deliberately avoided. |
| RC-04 credential/privacy boundaries | CONFIRMED | Yes | Yes | Candidate evidence proves retention in memory for transport while excluding persisted/diagnostic copies. |
| RC-05 multi-owner lifecycle | CONFIRMED | Yes | Yes | Issues 12 and 20 are candidate integration/migration corrections, not baseline defects. |
| RC-06 graph identity/closure/public boundary | CONFIRMED | Yes | Yes | Issue 10 protects metadata introduced by the Issue 6 fix. |
| RC-07 CLI result truth | CONFIRMED | Yes | Yes | Issue 19's checked output write was added while repairing this path. |
| RC-08 one realm per database | CONFIRMED | Yes | Yes | User selected Option B; identifiers are admission labels, not authentication. |
| RC-09 credential topology/risk | CONFIRMED | Yes | Yes | Live fixture has one agent; a separate two-agent Neo4j control proves global blast radius. |
| RC-10 frontend representation | CONFIRMED | Yes | Yes | Narrow-view browser proof is direct. MCP/A2A banner semantics are component-tested; live projection has zero A2A nodes. |
| RC-11 public documentation | CONFIRMED | Yes | Yes | Runtime was not implicated. Strict MkDocs passes. |
| RC-12 release oracles | CONFIRMED | Yes | Yes | This validates the harness, not a product fix. |

## Detailed verdict records

### RC-01 — release-version provenance had multiple writers

**Baseline tree and result.** A baseline collector binary built with the
linker-injected sentinel `1.0.0-validation` reports that sentinel from the
`version` command, but its emitted scan envelope reports
`meta.collector_version=0.1.0`. This proves a later artifact writer overwrote
release provenance.

**Candidate result.** The identically built candidate reports
`1.0.0-validation` in both the command output and the artifact envelope.

**Negative control.** The standalone `version` command proves linker injection
itself worked in both binaries; the difference is artifact construction, not a
bad build invocation.

**Evidence.** `rc01-baseline-version.json` has SHA-256
`9b75ab90ef530444a0d04351473de9a2c092c95ced73dd169071286a88164f3e`;
`rc01-candidate-version.json` has SHA-256
`601b7fe09f1f140850c6f80f973c3aa7f1828b58e44ac4245be6e4a1b35563e0`.
The candidate's focused version-envelope regression passes.

**Verdict: CONFIRMED.** Issue 1 is a true baseline release-provenance defect.

### RC-02 — authentication and observation claims were not consistently evidence-backed

**Baseline tree and result.** Real and protocol-backed controls reproduced
false or unusable authentication claims: public Open WebUI identity endpoints
were treated as privileged anonymous access; configured and looter observations
could conflict; successful MCP sessions using custom credential-bearing headers
could be labeled anonymous; three looters authored anonymous posture before
their proving inventory operation succeeded; empty credential placeholders were
emitted as observed exposed credentials; and the advertised A2A no-auth query
had no built-in runtime-evidence producer.

**Candidate result.** The candidate separates configured, observed, and
effective authentication tuples and selects them atomically with provenance.
Protected Open WebUI and 401 controls remain unproven; custom-header MCP remains
`unknown/configured_credential`; public Ollama, MLflow, and Qdrant lanes receive
anonymous posture only after the canonical inventory response shape; empty or
whitespace credential values emit no credential material; and the bounded A2A
nonexistent-task read produces the exact positive or protected diagnostic
without executing a skill.

**Negative controls.** Protected, malformed, wrong-shape, unsupported-version,
wrong-response-ID, noncanonical-detail, query-credential, arbitrary-header, and
empty-material cases remain unknown or are rejected. Official SDK A2A proof
records one read-only task lookup and zero executor calls, task saves, task
deletes, credential headers, or non-GetTask calls. Real protected Qdrant rejects
unauthenticated inventory without receiving affirmative graph properties.

**Real infrastructure.** The accepted 24-scenario run includes the public
Open WebUI, MCP, A2A, Ollama, MLflow, Qdrant, and empty/credential-bearing
configuration paths. Focused race tests cover the controls that cannot safely
or economically be multiplied in the full harness.

**Verdict: CONFIRMED.** Issues 2, 9, 15, 16, 35, 40, 44, 45, and 46 are true
baseline manifestations. Issue 43 is a candidate hardening correction found
while introducing the A2A observer; it is not an original baseline bug.

### RC-03 — protocol collection lost information, selected aliases nondeterministically, or escaped bounds

**Baseline tree and result.** Against the real streamable MCP fixture, baseline
and candidate both collect 29 nodes and 28 edges, but baseline drops the raw
`tasks` capability and serializes seven absent resource sizes as `0`. Two
same-ID configuration aliases flatten to one scalar `name=beta` instead of a
deterministic alias set. A slow optional standalone SSE GET held the collector
for 3 minutes 9 seconds despite its nominal 120-second per-server bound.

**Candidate result.** The same real MCP endpoint emits
`has_tasks_capability=true`; all nine resources omit ambiguous zero size; aliases
collapse to one deterministic node with `configured_names=["alpha","beta"]`;
and thirty repeated forward/reverse alias collections are stable. The candidate
disables the unused standalone SSE channel and completes the enforcing-gate run
immediately while retaining the full 14-tool/9-resource/4-prompt inventory.

**Negative controls.** Authentication-distinct and case-conflicting aliases
make zero network calls. The candidate retains normal streamable POSTs and
legacy SSE fallback. A2A alias ownership tests cover reversed order, successful
aliases, and failed-alias exclusion. The candidate passes
`go test -race -count=1 ./modules/mcp ./modules/a2a`.

**Loop control.** The hanging baseline was interrupted once after the bound was
already disproven. It was not repeatedly rerun.

**Evidence.** Baseline/candidate real artifacts are `baseline-mcp.json` and
`candidate-mcp.json`. Alias artifacts and thirty-run manifests are under the
independent evidence workspace. The exact accepted live-gate proof is recorded
under Issue 31 in the ledger.

**Verdict: CONFIRMED.** Issues 3, 4, 24, 25, 27, 28, and 31 are true product or
interoperability defects in the baseline path.

### RC-04 — credential-bearing transport material crossed trust boundaries

**Baseline tree and result.** Sentinel-bearing argv, URL user-info/query/
fragment material, default CLI target logging, and raw downstream error text
appear in baseline artifact or diagnostic paths. Strict ingest also permits
crafted MCP properties capable of persisting transport secrets.

**Candidate result.** The collector uses raw values only for in-memory identity
and transport, while the envelope carries sanitized endpoints and deterministic
argument hashes. The server rejects raw `args`, `env`, `headers`, `url`, and
noncanonical endpoints before graph mutation. Poison/tool-observer errors use
bounded stage categories. Empty credential values produce no Credential or
Identity graph facts.

**Negative controls.** An enforcing real MCP proxy returns 401 unless every
request carries the expected Basic and query credentials. The candidate obtains
the complete official Everything Server inventory through that gate, proving it
did not merely delete the values before transport, while whole-artifact and
stderr sentinel scans remain empty. Crafted imports and origin mismatches leave
the graph/database unchanged.

**Evidence.** `baseline-privacy.json` SHA-256 is
`dea4860fadc6a4d46d73d60a81f7a301a1ee89d7bc92aac45d3f9c5bcc78f0af`;
`candidate-privacy.json` SHA-256 is
`88111cc92a6facb07d1b0444c5a5a6da397aee82ad98e33912e33c07ada2e13d`.
The accepted real URL-secret lane and strict-ingest checks are recorded under
Issues 23, 26, 28–30.

**Verdict: CONFIRMED.** Issues 23, 26, 29, and 30 are true baseline privacy or
trust-boundary defects.

### RC-05 — multi-owner graph facts lacked safe identity and lifecycle transitions

**Baseline tree and result.** A complete Config plus configured-MCP refresh can
leave shared nodes/relationships property-incomplete and withhold publication.
Exact owner transfer is treated as data loss, and an `all_dependencies` owner
rotation unions stale dependency groups instead of replacing the complete
group.

**Candidate result.** Per-owner semantic fingerprints preserve the last
coherent public fact, distinguish exact agreement from conflict, retire with
their owner, and support exact ownership transfer. Complete
`all_dependencies` groups replace atomically; partial groups remain fail-closed.
The same lifecycle matrix passes the Neo4j 4.4 fallback writer, Neo4j 4.4 with
APOC, and Neo4j 5.x.

**Negative controls.** Changed owner properties, missing legacy fingerprints,
partial dependency groups, future schema versions, and nonempty legacy stores
remain rejected or incomplete without certifying the changed fact. Repeated
exact refreshes remain idempotent.

**Patch-composition qualification.** Issues 12 and 20 are real candidate
integration requirements: Issue 12 corrected the first Issue 6 fingerprint
composition, and Issue 20 added an honest upgrade boundary for graphs created
before fingerprints existed. They are not independent defects in the untouched
baseline.

**Verdict: CONFIRMED.** Issues 6, 21, and 22 are true baseline lifecycle
defects. Issues 12 and 20 are valid candidate-integration corrections.

### RC-06 — graph identities, endpoint closure, and public/internal properties were inconsistent

**Baseline tree and result.** Committed extraction accepts an arbitrary locator
such as `hf://TinyLlama/stories260K.gguf`, exits successfully, and emits two
training-signal nodes plus two `EXTRACTED_FROM` edges whose source endpoint is
missing. It therefore combines dangling edges with a noncanonical source ID.

**Candidate result.** The arbitrary locator is rejected. Supplying the
canonical SHA-256 object ID emits one empty `reference_only` AIModel endpoint,
two signal nodes, and two closed edges; strict ingest publishes the result at
revision 5. Structured node, edge, finding, finding-detail, and posture-export
responses contain zero internal `observation_fact_fingerprints` occurrences.

**Negative controls.** The baseline strict importer rejects the dangling
artifact with two validation errors. Raw Cypher remains intentionally raw;
only structured public surfaces are scrubbed.

**Evidence.** Baseline arbitrary artifact SHA-256:
`56e61e8277fe8c235607ef03e51e34dad79598d2dc896c98185d8856a624ec8f`.
Candidate canonical artifact SHA-256:
`e9e9eee871cc414b16075de63b114af53c6d97de5be0cbc5e815c99b25815400`.
Candidate rejection stderr SHA-256:
`73f79c36897874bba8330372d9d1d3f7d725868bbde488b9e5cbe778772bd854`.
Public-response evidence files and hashes are retained in the independent
evidence workspace.

**Patch-composition qualification.** Issue 10 protects internal fingerprints
introduced by the Issue 6 repair. It is a valid candidate integration fix, not
an independent baseline defect.

**Verdict: CONFIRMED.** Issues 8 and 13 are true baseline graph-contract
defects; Issue 10 is valid candidate hardening.

### RC-07 — CLI success and diagnostics contradicted pipeline/output failure

**Baseline tree and result.** Importing a deliberately unpublished typed result
prints `Ingest complete`, reports 49/45 rows, and exits zero even though the
database records `completed_with_errors`, complete collection, incomplete
projection, unpublished state, no publication revision, and failed stages.
The baseline also loses typed partial-write context when an underlying pipeline
error is returned.

**Candidate result.** The CLI prints the typed outcome, projection/publication
state, writer counts, and first unhealthy required stage, retains the causal
error, and exits nonzero. A failing output writer returns its sentinel error
instead of silently losing the diagnostic.

**Evidence.** `rc07-baseline-unpublished.json` and its database row are retained
in the evidence workspace. Baseline stdout SHA-256 is
`cde6dd740a1eccf5a0fe46e68f533f8f45f5e214270e802b780cbd2193606c5e`.
The candidate passes `go test -race -count=1 ./server/cli`.

**Patch-composition qualification.** The checked diagnostic write in Issue 19
is a valid reliability correction introduced while adding the richer Issue 7
report. The removed dead helper is maintenance cleanup. Neither should be
counted as an independent baseline functionality bug.

**Verdict: CONFIRMED.** Issues 7 and 14 are true baseline CLI defects; the
functional part of Issue 19 is candidate-integration hardening.

### RC-08 — host-local/private-realm facts shared unsafe global lifecycle

**Baseline tree and result.** Independently complete Host A and Host B
collections can collide on host-local IDs and coverage roots, allowing Host B
to replace or merge Host A facts in one database even though the product
described central collection.

**Candidate result.** Under the user-selected Option B contract, every v3
artifact carries explicit `host_id` and `network_realm_id`; each PostgreSQL/
Neo4j storage pair is bound to one immutable versioned host/realm tuple plus a
canonical `storage_pair_id`. Startup checks both stores before ordinary schema
mutation and every ingest rechecks admission. Fresh binding, exact restart,
one-sided empty recovery, and both Neo4j 4.4/5.x paths pass.

**Negative controls.** Wrong host, wrong realm, crossed database pairs, future
marker version, nonempty unbound legacy state, one-sided nonempty marker loss,
and runtime marker tampering fail closed. The wrong-origin artifact returns 409
with revision, graph totals, scan count, publication count, and finding count
unchanged. Storage disagreement returns a sanitized 503.

**Security qualification.** These nonsecret labels prevent accidental mixing
under the single-user model. They are not signatures and do not authenticate a
hostile artifact. One realm per database is an intentional v1 product boundary,
not central multi-realm isolation.

**Verdict: CONFIRMED.** Issue 18 is a true release-blocking baseline architecture
defect, and Option B enforces the selected truthful scope.

### RC-09 — credential reachability, attribution, and risk used the wrong topology or grouping

**Baseline tree and result.** Runnable credential-reach prediction recognizes
environment locations but misses equivalent header/argv/URL credentials. Risk
and high-entropy attribution follow the env-only edge. Blast radius groups by
individual Config credential node, so two agents using distinct nodes with the
same value hash can write a shared master radius of one.

**Candidate result.** The candidate traces the canonical
Agent→Server→Identity→Credential topology independently of credential location,
requires observed exposed `value_hash` material, excludes synthetic identity
hashes, chooses a deterministic seven-node/five-raw-edge witness, and computes
global distinct-agent blast radius at the shared hash grain.

**Real projection.** The live API returns eight credential-chain rows; every
row has confidence 0.6, six hops, and header attribution `Authorization`. Three
exact LiteLLM upstream targets each have a public finding, seven evidence nodes,
five raw evidence relationships, and one synthetic `VALUE_HASH_MATCH`. The two
high-entropy rows have correct attribution: one cross-service gate and one
unattributed LiteLLM master key. ContextForge risk is 57.5 with range
[37.5,57.5]; the later full-data cursor score is 60.17 because the projection
contains additional facts.

**Negative controls.** Identity-only, masked, non-high-entropy, wrong topology,
and missing-observation cases do not join. The retained live fixture has one
agent and therefore a radius of one; an isolated two-agent Neo4j control proves
the corrected radius is two and remains idempotent.

**Verdict: CONFIRMED.** Issues 32, 33, and 37 are true baseline analysis defects.

### RC-10 — frontend controls or evidence representation contradicted product state

**Baseline browser result at 484×779.** The New Scan dialog spans
`y=-102.8125` to `881.8125`, has `overflow-y: visible`, and places Close at
`y=-85.8125` to `-69.8125`, completely outside the viewport. The primary nav
has no accessible names/titles and clips Scans, Queries, and Rules beyond the
right edge. Its five artifact-producing examples omit the now-required host and
realm flags.

**Candidate browser result at 484×779.** The dialog stays within
`x=0..484`, `y=16..763`, has `overflow-y: auto`, and scrolls through all
content. Close is reachable and dismisses the dialog. Every route is inside the
viewport with an accessible name/title. The lens strip is capped to 452 pixels
and horizontally scrolls its 1152-pixel contents; Attack Surface, Topology, and
Chokepoints visibly switch to 13/14, 155/154, and 190/165 edge/node views. All
five collector examples contain both `--host-id <host-id>` and
`--network-realm-id <network-realm-id>`; ingest-only remains unchanged. Browser
console warning/error records are empty.

**Evidence representation.** The live reachable MCP API tuple is
`status=reachable`, observed `none/unauthenticated/anonymous_probe_succeeded`,
with the same effective tuple sourced from `observed`, and
`has_tasks_capability=true`. Focused component tests prove this renders
`Directly verified`, an unreachable probe renders `Verification failed`, an
exact A2A anonymous read probe is described without claiming skill execution,
401/403 is an observed authentication boundary, inconclusive results remain
unknown, and orphan/noncanonical positives are not trusted. Markdown export
leads with the effective tuple while retaining configured and observed lanes.

**Frontend gates.** Targeted representation/responsiveness suite: 5 files and
23 tests passed. Full Vitest: 52 files and 232 tests passed. ESLint, `tsc -b`,
and the Vite production build passed. Vite emitted only its nonblocking IIFE-name
and chunk-size advisories.

**Browser limitation.** The current retained projection has zero A2A nodes, so
there is no truthful live A2A drawer to click. Automated React Flow node-click
attempts did not open a drawer and were stopped instead of looped; there were no
console errors. Banner semantics are therefore accepted from the exact
component controls plus the live API tuple, while navigation/dialog/lens
behavior is direct baseline/candidate browser evidence. Clipboard event
observation was similarly unavailable, but the DOM contained the exact command
and the click itself succeeded.

**Patch-composition qualification.** Issues 41 and 47 are integration fixes for
new A2A evidence and v3 origin requirements. They are not original baseline
defects. Issues 5, 11, and 36 are true baseline UI defects.

**Verdict: CONFIRMED, with the browser-automation limitation stated above.**

### RC-11 — public documentation described nonexistent fields or topology

**Baseline source comparison.** The graph reference lists
`ExtractedTrainingSignal.kind`, `source_model`, and `sample_count`, while the
extractor emits token-level `token_index`, `token_string`, `magnitude`,
`z_score`, `confidence`, `source_model_id`, `engagement_id`, `method`, and
`extracted_at`. The README depicts one Credential node shared by Config and
LiteLLM plus `Agent→CAN_REACH→LiteLLMGateway`; production retains distinct
collector-owned credentials correlated by value hash and reaches the upstream
Credential. README/current architecture docs claim 25 nodes, 30 edges, and 18
raw edges.

**Candidate comparison.** Current docs list the exact extractor fields and the
empty `reference_only` AIModel endpoint, show distinct configured/master/
upstream credentials with synthetic `VALUE_HASH_MATCH`, and describe
`Agent→CAN_REACH→upstream Credential`. `sdk/ingest/kinds.go` and its race-enabled
tests establish 23 public node kinds, 20 raw edge kinds, and 12 composite edge
kinds, 32 total; current docs use those values and include
`CREDENTIAL_REACH_VERIFIED` and `PUBLIC_ACCESS_OBSERVED`.

**Negative search and strict build.** No current README/docs occurrence remains
for the stale `25/30/18` cardinalities outside deliberately historical material.
`PATH=/tmp/agenthound-docs-venv/bin:$PATH make docs-check` passes strict MkDocs.
The displayed MkDocs 2.0/Material notice is an upstream future-compatibility
notice, not a broken link, orphan, or build failure.

**Verdict: CONFIRMED.** Issues 17, 34, and 42 are true documentation-contract
defects and do not imply a runtime failure.

### RC-12 — release oracles could declare incomplete coverage green

**Baseline oracle result.** The harness can serialize 24 planned scenarios but
derive `collector_status=compatible` from an empty results file because its
status depends on a mutable failure counter. The credential-chain oracle also
accepts one of three expected upstream targets by using `any(...)` and the first
matching row.

**Candidate result.** Compatibility requires exactly the 24 named, unique,
object-valued primary pass records, no unexpected/duplicate/malformed rows, no
diagnostic records, and a matching failure counter. Cross-service checks require
the exact three-target set in graph edges, public findings, and persisted
witnesses, with exact evidence for every target.

**Negative controls.** Missing, duplicate, unexpected, malformed, bad-status,
counter-mismatch, diagnostic, and one-of-three-target projections are all
rejected. The exact valid 24-record set remains green. The accepted final run
records 24 planned, 24 results, 24 passes, and zero collector failures.

**Verdict: CONFIRMED as validation-infrastructure defects.** Issues 38 and 39
must not be counted as product bugs; retained product data already contained all
three credential-chain targets.

## Post-checkpoint Stack 05 composition findings

These records were found while isolating and revalidating RC-09. They are true
findings against the composed candidate, but neither is a newly demonstrated
defect in untouched baseline `1e45601`; adding them to the baseline totals would
be misleading.

### S5-F1 — v3 origin migration missed a compiled live-test fixture

With live Neo4j and PostgreSQL enabled, the compiled campaign vertical failed
strict ingest because both required `meta.origin` fields were absent. Adding
origin only to its hand-built base graph then proved the spawned collector also
lacked the public host/realm environment contract. The correction supplies one
stable synthetic host/realm pair to both layers; validation remains strict.

This is a coverage defect, not evidence of an originless production path. Before
the correction, the skipped integration could not reach the behavior its name
claimed to test. Afterward the complete compiled collector → credential gate →
ingest → source-agent-only path passed three race-enabled repetitions on Neo4j
4.4.48/PostgreSQL 16 and three on Neo4j 5.26/PostgreSQL 16.

### S5-F2 — property-neutral LiteLLM output produced null `via_gateway`

The retained real projection had all three expected credential-chain targets
and exact seven-node/five-raw-edge-plus-synthetic witnesses, but every
cross-service `CAN_REACH` edge omitted `via_gateway`. The looter correctly owns
only a property-neutral gateway reference; the processor incorrectly assumed
that reference always had `name`. A synthetic integration gateway with a name
masked the real producer shape.

The correction uses gateway name, endpoint, then immutable object ID, in that
order. It preserves the looter's ownership boundary while guaranteeing a
truthful traceable value. The live integration fixture now omits both display
properties and requires the object-ID fallback. The processor passed ten
race-enabled repetitions and the exact database integration passed five on
Neo4j 4.4.48 and five on Neo4j 5.26. Detection targets, confidence, graph
topology, exact evidence, and blast radius were already correct; this was a
real explanatory-metadata defect, not a false finding.

Both corrections are included in Stack 05 commit `2232e05`. The exact file and
hunk inventory, reproduction errors, and cleanup record are in
`pr-slice-plan.md`. Stack 06 owns the matching real-infrastructure oracle guard
for non-null truthful `via_gateway`.

## Step 3 conclusion: findings and fixes are independently credible

The candidate is materially better than the untouched baseline on every tested
root-cause group. The strongest release-blocking findings—false authentication
claims, secret boundary leaks, graph lifecycle/publication failure, cross-host
identity collision, incorrect credential topology, false CLI success, and
unusable UI controls—have baseline reproductions, candidate corrections, and
negative controls. The verification also caught seven real composition issues
in temporary fixes before they could be mistaken for baseline defects or merged
unreviewed.

No new unresolved release-blocking functionality defect surfaced during this
independent pass. That statement is bounded to the tested feature set and pinned
real infrastructure; it is not a guarantee against future upstream drift or
novel offensive-technique bypasses.

## Step 4 conclusion: representation and public contracts are coherent

For the retained final projection, collector artifacts, Neo4j, PostgreSQL,
structured APIs, query results, and the tested UI surfaces agree on published
inventory, findings, credential-chain evidence, and authentication provenance.
The candidate frontend and documentation no longer contradict the underlying
producer/query contracts in the tested cases.

The optimal next action is not to merge the 221-file snapshot wholesale. Slice
the candidate by the twelve reviewed root-cause boundaries, starting with
RC-08/RC-04/RC-02/RC-05, and preserve this branch as the comparison checkpoint.
Each slice should carry the relevant baseline reproduction, candidate regression,
and the exact documentation update. Run the full integrated harness and
`make prerelease` once again only after the accepted slices are assembled into
the intended release branch.

## Final stacked-candidate conclusion

The six accepted slices are now assembled through
`codex/release-stack-06-ui-docs-oracles` commit `4fe862a`. The required final
fresh 24-scenario real-infrastructure run, production database/API/browser
reconciliation, complete Go race suite, UI/docs gates, and `make prerelease`
all pass. The final run contains exactly 24 unique primary passes and zero
diagnostics/failures; its cross-service projection contains exactly three
truthful findings with complete persisted evidence and a non-null gateway
identifier on every current edge.

No new release-blocking true-positive defect surfaced in this final integrated
pass. S5-F1 and S5-F2 remain correctly classified as post-checkpoint composition
findings rather than additional untouched-baseline bugs. Stack 06's tightened
gateway oracle rejects the retained pre-fix null projection and accepts the new
truthful projection, closing that regression path.

This is an evidence-bounded conclusion, not a claim that future upstream
releases or novel offensive techniques can never expose another issue. The
current supported feature set works as represented against the pinned real
infrastructure tested here. No release tag or remote push was performed; the
user explicitly deferred promotion of the unreleased v0.9.0 development tree.

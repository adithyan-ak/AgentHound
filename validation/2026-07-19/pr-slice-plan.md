# AgentHound v1.0 Candidate Review Stack

## Objective

Convert the validated 221-file candidate checkpoint into reviewable changes
without losing cross-component invariants or pretending coupled fixes are
independent. The stack is constructed from the untouched baseline
`1e45601c4d004247da60c0f0e796debfb3cc37fc`. Its final tree must be byte-equal
to product checkpoint `6428f13` except for post-checkpoint corrections that are
independently reproduced, minimally patched, and called out by exact diff in
this ledger.

The configured `origin` is public. No review branch is pushed until the user
explicitly authorizes the exact branch and remote.

## Construction status

### Stack 01 — complete

- Branch: `codex/release-stack-01-realm-v3`
- Commit: `ee070b7` (`feat(storage): bind ingest v3 to one collection realm`)
- Parent: untouched baseline `1e45601`
- Scope: 73 files, 2,346 insertions, 147 deletions
- Public remote: not pushed

The staged-only tree passed `gofmt -l .`, `go build ./...`, `go vet ./...`, and
`go test ./... -race`. The focused Scan Manager and Scan Import suite passed
28/28 tests, followed by UI lint and production build. `make docs-check` passed
with a strict MkDocs build.

Slicing exposed one genuine dependency rather than a product defect: the
existing strict A2A risk-score import fixture became invalid when v3 made
`meta.origin` mandatory. Stack 01 adds only a canonical fixture origin; the
later configured-versus-observed auth rewrite remains in stack 04. The first
focused UI run likewise proved that the longer origin-bearing commands require
the candidate's viewport-bounded shared dialog class, so that two-token class
change is retained with Issue 47 instead of being deferred as unrelated UI.

Real database verification used disposable loopback-only stores and then
removed them:

- Neo4j 4.4 + PostgreSQL 16 accepted a collector-generated v3 artifact with the
  exact configured origin and published a complete projection.
- Changing only `host_id` returned `409 COLLECTION_REALM_MISMATCH`; PostgreSQL
  still contained exactly the one accepted scan row.
- With Neo4j unavailable, ingest returned the sanitized
  `503 STORAGE_BINDING_UNAVAILABLE` after the driver's 30-second retry budget;
  no scan row was added.
- Neo4j 5.26 + PostgreSQL 16 initialized a fresh pair and restarted with the
  same markers successfully.
- A second independently initialized pair used a different UUID and realm.
  Starting against pair A's PostgreSQL and pair B's Neo4j exited 1 before
  serving, reported the marker mismatch, and left both original markers
  unchanged.

No new release-blocking defect was found in stack 01.

### Stack 02 — complete

- Branch: `codex/release-stack-02-collector-truth`
- Commit: `acad077` (`fix(collector): preserve MCP truth without leaking transport secrets`)
- Parent: stack 01 commit `ee070b7`
- Scope: 44 files, 4,748 insertions, 392 deletions
- Public remote: not pushed

The staged-only tree passed `gofmt -l .`, `go build ./...`, `go vet ./...`, and
`go test ./... -race`. Focused collector, CLI, Config, embedding, MCP,
MCP-poison, SDK-ingest, and strict-ingest race suites passed. The alias and
ambiguous-profile controls passed 30 consecutive race-enabled repetitions.
Dependency-boundary and collector-size gates passed; the stripped linux/amd64
collector was 11,006,136 bytes against a 12,012,132-byte limit. Strict MkDocs
also passed.

Slicing proved two trust-boundary dependencies that belong in this stack:

- Config's canonical `Identity`/`Credential` topology is emitted in the same
  privacy-sensitive extraction functions as argv, inline environment, URL
  query, and URL-password discovery. Stack 02 therefore owns producer topology;
  stack 05 owns only the downstream reachability, grouping, and risk analysis.
- Strict configured/observed authentication tuple validation and MCP opaque
  header authentication truth share the collector and validator hunks already
  required for transport-secret closure. They remain here; stack 04 owns A2A
  active observation and every effective-auth consumer.

Real verification used the retained release fixture network with a staged-only
linux/arm64 collector (SHA-256
`67963eefc4f1d845bcf2823d4bac979de130f152ead56182633bb20113886647`):

- An enforcing MCP credential gate returned 401 for missing and wrong
  credentials and advanced to protocol negotiation only for the exact secret.
- A URL-secret MCP scan completed with 29 nodes and 28 edges: 14 tools, nine
  resources, four prompts, and task capability. The public endpoint was
  `http://mcp-credential-gate:3002/mcp`; all URL credential components were
  marked redacted; authentication was reported as configured Basic evidence;
  absent resource sizes stayed absent.
- The artifact, stdout, and stderr contained zero occurrences of every secret
  sentinel.
- A Config fixture produced a three-argument stdio identity with only argument
  hashes, a sanitized HTTP endpoint, and four canonical credential nodes for
  argv, inline-environment, URL-query, and URL-password sources. No raw
  argument, environment, header, URL credential, or credential value survived
  in the artifact or process output.

After the deferred candidate changes were restored, the reconstructed product
tree was byte-identical to checkpoint `6428f13` with only the private working
ledger intentionally excluded. No new release-blocking defect was found in
stack 02.

### Stack 03 — complete

- Branch: `codex/release-stack-03-graph-lifecycle-cli`
- Commit: `2084a63` (`fix(graph): preserve owner-scoped publication truth`)
- Parent: stack 02 commit `acad077`
- Scope: 22 files, 2,959 insertions, 350 deletions
- Public remote: not pushed

The staged-only tree passed `gofmt -l .`, `go build ./...`, `go vet ./...`, and
`go test ./... -race`. Graph, ingest, and server-CLI race suites then passed 10
consecutive repetitions. Strict MkDocs passed using a fresh disposable
virtualenv populated only from `docs/requirements.txt`; the first invocation
had stopped before build because the isolated worktree correctly lacked an
ignored local virtualenv.

Live graph verification used three disposable loopback-only databases and
removed them afterward:

- Neo4j 4.4.48 without APOC exercised the fallback relationship writer.
- Neo4j 4.4.48 with APOC 4.4.0.40 exercised `apoc.merge.relationship`.
- Neo4j 5.26.28 exercised the 5.x schema syntax and fallback writer.
- The complete integration suite passed on all three. A concise second pass of
  the new future/legacy schema guard, dependency-group rotation, exact owner
  transfer, and compatible co-owner lifecycle tests also passed under `-race`
  on every target.

An independent staged collector/server control used binaries with SHA-256
`d03abf1c2a307b9914ff5cef5b8d54991ece399d8eb4dfa3c097847a235eb247`
and `b082e03291e7d5797b1d02fe78c7e5d1832b7787cda7eebee650b6e5b6be87b4`:

- The collector produced a v3 Config artifact with seven nodes and three raw
  edges. The CLI ingested it into fresh Neo4j 5.26/PostgreSQL 16 stores, exited
  0, and reported complete/complete, published revision 1, and exactly 7/3
  write rows.
- PostgreSQL independently recorded every lifecycle stage complete and
  published at revision 1. Neo4j contained seven public nodes and four public
  edges after the one derived `POISONED_INSTRUCTIONS` edge. The structured API
  reported the same 7/4 projection at revision 1.
- Neo4j contained internal per-owner fingerprints on all seven raw nodes and
  three raw edges. Node lists, edge lists, node detail, and a three-hop
  neighborhood returned zero fingerprint properties.
- An internally consistent partial artifact wrote 7/3 rows but withheld
  publication. The CLI printed the typed partial outcome, incomplete
  projection, unavailable revision, exact row counts, and the first unhealthy
  required stage, then exited 1. PostgreSQL retained published revision 1 and
  marked the attempt `completed_with_errors`/unpublished; structured reads
  returned `409 PROJECTION_CONFLICT` instead of exposing the mutable graph.
- A deliberately inconsistent partial test envelope was rejected during
  validation before this control, confirming aggregate-state validation. It
  was corrected once by making one concrete child outcome partial; no product
  patch was needed.

After deferred changes were restored, the reconstructed product tree again
matched checkpoint `6428f13` byte-for-byte except for the intentionally omitted
private ledger. No new release-blocking defect was found in stack 03.

### Stack 04 — complete

- Branch: `codex/release-stack-04-auth-evidence`
- Commit: `e6a6af7` (`fix(auth): require observed runtime evidence across consumers`)
- Parent: stack 03 commit `2084a63`
- Scope: 73 files, 4,883 insertions, 395 deletions
- Staged tree: `cfa00d42e5ffcf94d8f26b724e1a0b3062fe4fc0`
- Public remote: not pushed

The isolated tree passed `gofmt -l .`, `go build ./...`, `go vet ./...`, and
`go test ./... -race` both before and immediately before commit. Every changed
collector/ingest/analysis package then passed 10 consecutive race-enabled
runs. The frontend passed all 229 tests across 50 files, ESLint, and the Vite
production build; strict MkDocs passed using the pinned disposable environment
created from `docs/requirements.txt`.

Slicing exposed two real dependency boundaries, neither a new runtime defect:

- The new effective-auth consumer integration test used three generic fixture
  helpers that originally lived only in stack 05's untracked cross-service
  integration file. The helpers are defined in stack 04 so this parent compiles
  independently. Stack 05 moves their definitions back into the cross-service
  test when that file enters the stack, restoring the monolithic candidate
  bytes.
- `CanReach` applies its effective-auth predicate and canonical
  `MCPServer -> Identity -> Credential` resource witness in the same Cypher
  statement. Splitting those clauses would create a knowingly stale query, so
  stack 04 owns that complete credential-to-resource path migration. Stack 05
  still owns cross-service value-hash grouping, upstream-credential
  correlation, global blast radius, and credential-risk consumers.

Real A2A verification used the staged-only linux/arm64 collector (SHA-256
`d0a17049d4be5bad1cb2970836cabcb79b1e4dacdf140aaca4d3a1a072dac27d`)
against the retained official-SDK fixture:

- One six-target scan emitted 19 nodes and 14 edges. The v1 and v0.3 lanes
  reported exact nonexistent-task evidence as observed anonymous protocol
  access; the protected lane retained its declared API-key/weak posture and
  reported `authentication_required`; the version-ambiguous lane remained
  unknown rather than being guessed anonymous.
- Every dynamic lane received exactly one `GetTask` request. Executor calls,
  non-GetTask calls, task-store saves, and task-store deletes all remained
  zero.
- A separate protected-target run supplied a unique operator bearer. The card
  request could use it, but the bounded anonymous protocol probe did not:
  `credential_header_requests` stayed unchanged. The secret sentinel was
  absent from the graph artifact.

Real looter verification matched the seeded upstream predicates exactly:

- Ollama: one model, one `PROVIDES_MODEL`, confirmed embedding capability,
  complete collection, zero partials.
- MLflow: two experiments, one run, one registered model/version/resource,
  complete collection, zero partials.
- Qdrant: two sorted collections, four total points, four bounded sampled
  resources, complete collection, zero partials.
- Open WebUI: verified protected posture, one redacted upstream credential,
  and a configuration-only Ollama backend reference without fabricated active
  discovery/auth facts.

The same four looters were deliberately aimed at an unrelated live
OpenAI-compatible decoy. Each artifact was partial with the exact 404
diagnostic, one neutral attempt node, zero resource/credential nodes, and zero
edges. `loot_observed=true` was initially investigated as a possible false
affirmation, then closed as a documented action-provenance fact: successful
identity/auth claims require the separate product-shaped response and
`probe_status=verified`, which were absent. No risk or UI consumer treats the
attempt marker as verification.

Live analysis verification used disposable Neo4j 4.4 and 5.26 containers and
removed both afterward. On each version, the complete prebuilt, processor, and
risk-score packages passed three race-enabled repetitions with integration
tests active. This exercised paired effective tuple derivation, per-edge trust
assessment, direct and credential-path `CAN_REACH`, cross-protocol and
confused-deputy eligibility, weighted paths, and Agent/A2A/MCP risk consumers.

Finally, the retained release API and browser were compared against the same
published projection:

- API page revision `5` contained five MCP servers. A bearer-protected server
  exposed configured, observed, and effective `bearer/moderate` tuples with
  source `observed`; an anonymously reachable server retained configured
  unknown while exposing observed/effective
  `none/unauthenticated/anonymous_probe_succeeded`, also source `observed`.
- Explorer Properties and Evidence rendered those fields exactly without
  collapsing provenance. The anonymous server's remediation correctly asked
  the operator to add authentication. The rendered view had no browser console
  warnings/errors or contradictory/clipped labels.

Harness-only diagnostics were resolved once and not looped: `go vet` first
identified the cross-stack test-helper dependency; the first docs command
lacked the ignored virtualenv on `PATH`; one decoy command mistakenly invoked
the Linux binary on the macOS host; and the first browser tab binding reused a
stale generic identifier. None reached product code or target state, and each
was corrected at the execution boundary before evidence was accepted.

After deferred changes were restored, a full file-by-file comparison against
checkpoint `6428f13` was empty for all product files. No new release-blocking
defect was found in stack 04.

### Stack 05 — complete

- Branch: `codex/release-stack-05-credential-analysis`
- Commit: `2232e05` (`fix(analysis): correlate credential evidence at value-hash grain`)
- Parent: stack 04 commit `e6a6af7`
- Scope: 16 files, 715 insertions, 129 deletions
- Staged/commit tree: `a04b7d1bc1777d3aa012eb0c21f06fb405e22b37`
- Public remote: not pushed

The staged-only tree passed `gofmt -l .`, `go build ./...`, `go vet ./...`, and
`go test ./... -race` before the last correction and again immediately before
commit. Changed analysis, processor, risk-score, and ingest packages passed 10
consecutive race-enabled repetitions; after S5-F2, the processor package alone
passed another 10. Strict MkDocs passed after the documentation correction.

The retained real projection independently reconciled collector and server
outputs rather than trusting one summary counter:

- The findings API contained exactly three
  `credential_chain_reference` findings for the Cursor source agent: masked
  Anthropic and OpenAI provider references plus one hashed virtual-key
  reference. Each had confidence 0.95 and explicit `reference_only` evidence;
  none was mislabeled as observed upstream secret material.
- Each finding detail contained the exact continuous seven-node witness:
  AgentInstance → MCPServer → Identity → configured header Credential →
  LiteLLM master Credential → LiteLLMGateway → target Credential.
- Each witness contained exactly five ordered raw relationships
  (`TRUSTS_SERVER`, `AUTHENTICATES_WITH`, `USES_CREDENTIAL`, and two
  `EXPOSES_CREDENTIAL`) plus one synthetic `VALUE_HASH_MATCH` from the
  configured Authorization credential to the LiteLLM master credential.
- The graph API contained exactly three cross-service `CAN_REACH` edges with
  six hops, confidence 0.95, risk weight 0.1, one common merge hash, seven
  evidence node IDs, five raw relationship IDs, and the exact synthetic tuple.
  Both observed join credentials had blast radius one, which agrees with the
  one-agent retained corpus.

Disposable database verification exercised the global aggregation and exact
witness logic on Neo4j 4.4.48 and 5.26. Each version passed five race-enabled
repetitions with two same-hash agents, a duplicate path, and an identity-only
decoy. Every eligible credential received global blast radius two, the decoy
remained unenriched, and repeat execution preserved one deterministic edge per
agent/target. The compiled collector → credential-gated MCP probe → production
ingest → source-agent-only campaign vertical passed three race-enabled
repetitions on each Neo4j version with PostgreSQL 16. The three disposable
Stack 05 containers were then removed; the retained release databases and
server were not mutated by these controls.

Two true post-checkpoint composition findings were reproduced and corrected.
They are intentionally outside the frozen 47-issue baseline accounting:

#### S5-F1 — compiled campaign live test could not emit valid ingest v3 origin

**Reproduction.** Activating
`TestIntegrationCompiledCampaignExportProbeIngestPromotesOnlySourceAgent`
against fresh Neo4j/PostgreSQL first failed strict ingest with
`meta.origin.host_id: host_id is required` and
`meta.origin.network_realm_id: network_realm_id is required`. Supplying origin
only on the hand-built base artifact exposed the second boundary: the compiled
collector subprocess still failed because its environment lacked
`AGENTHOUND_HOST_ID` and `AGENTHOUND_NETWORK_REALM_ID`.

**Classification and impact.** This is a valid test-fixture defect introduced
when v3 made origin mandatory. It is not evidence that production ingest
accepts an originless artifact; the opposite is true. The defect meant this
normally skipped live integration could never exercise the compiled vertical
path against real databases and therefore created a coverage blind spot.

**Minimal correction.** The base fixture now carries stable synthetic
`campaign-fixture-host` / `campaign-fixture-realm` origin values, and the
compiled collector receives the same values through its public environment
contract. No validator or production admission rule was weakened.

**Verification.** The complete vertical passed `-race -count=3` on Neo4j 4.4.48
with PostgreSQL 16 and again on Neo4j 5.26 with PostgreSQL 16. This is an intentional
two-hunk delta from checkpoint `6428f13` in
`server/internal/ingest/campaign_vertical_integration_test.go`.

#### S5-F2 — real cross-service edges omitted the promised gateway identifier

**Reproduction.** The retained graph had the exact three expected
cross-service edges and complete canonical witnesses, but `via_gateway` was
null on all three. The processor assigned only `winner.gateway.name`; the
LiteLLM looter intentionally emits a property-neutral gateway reference so it
does not overwrite fingerprint-owned name/auth properties. A standalone loot
collection therefore guarantees the gateway object ID, not a name or endpoint.
The integration fixture hid this by supplying both a synthetic name and
endpoint, while the operator and architecture docs promised `via_gateway` as
edge evidence.

**Classification and impact.** This is a candidate-integration
evidence-fidelity bug, not a false-positive finding or broken topology.
Detection targets, confidence, exact evidence nodes/edges, blast radius, and
publication were all correct, but one promised explanatory field disappeared
on real producer output. It must not be advertised as an untouched-baseline
defect.

**Minimal correction.** The processor now chooses the first truthful stable
identifier from gateway name, endpoint, and immutable object ID. It does not
make the looter claim fingerprint-owned properties. The integration fixture
now matches the real property-neutral node and requires the object-ID fallback;
a unit guard pins the Cypher fallback, and both operator and architecture docs
state the precedence.

**Verification.** The corrected fixture passed the processor suite under
`-race -count=10`, then the exact live-database integration under
`-race -count=5` on Neo4j 4.4.48 and separately on Neo4j 5.26. Stack 06 must add
`via_gateway` to the exact real-infrastructure oracle so this representation
regression cannot return silently. The code/test/doc changes are intentional
post-checkpoint deltas from `6428f13`.

No unresolved release-blocking defect remains from Stack 05. The evidence-field
correction changes explanatory metadata only; the retained revision-5 database
was intentionally left untouched rather than rewritten merely to make old
evidence display the patched fallback.

## Why this is a stack, not parallel PRs

The final fixes share several contract files:

- `sdk/ingest/ingest.go` and fixtures carry the v3 origin boundary used by every
  artifact producer and the server.
- `server/internal/ingest/validator.go` enforces origin, transport privacy, and
  authentication evidence in one trust boundary.
- `server/internal/ingest/pipeline.go` performs storage admission before any
  mutation and preserves owner-scoped graph contributions for the lifecycle
  writer.
- `modules/config/collector.go`, `modules/mcp/collector.go`, and their tests
  jointly own origin propagation, secret-safe identity, aliases, and auth
  evidence.
- `docs/reference/graph-model.md`, `docs/reference/cli.md`, and
  `docs/operator/security.md` describe multiple layers of the same contract.

Splitting these changes into branches that all target `main` would duplicate
shared hunks, create misleading intermediate states, and make conflict
resolution part of security semantics. A linear stack keeps every parent
reviewable and gives each child a narrow diff against the already-reviewed
contract below it.

## Stack order

### 01 — `codex/release-stack-01-realm-v3`

**Purpose:** establish the selected one-host/private-realm-per-database boundary
and wire v3 before later fixes add more v3 evidence.

**Issues:** RC-08 / Issue 18, RC-01's release-version single-writer cleanup,
plus candidate-integration Issue 47 because the UI must not advertise commands
that cannot create v3 artifacts. RC-01 is included here because every artifact
writer already had to be replaced to add v3 origin; splitting the stale
version assignment from those exact functions would create artificial shared
hunks without an independently reviewable intermediate behavior.

**Owns:**

- `sdk/ingest/origin.go`, origin metadata, and v2→v3 wire version.
- Release-version single-writer behavior in the artifact-producing CLI paths.
- Collector host/realm flag and environment resolution, explicit origin
  propagation through every artifact-producing verb/action.
- PostgreSQL and Neo4j storage markers, pre-migration bootstrap admission,
  runtime admission, 409/503 API mapping, and exact failure ordering.
- Server storage-pair configuration, Docker/s6/Makefile deployment wiring.
- v3 fixture migration and the Scan Import/New Scan origin workflow.
- Only the origin/storage/deployment portions of shared CLI/API/graph/security
  documentation.

**Must exclude:** secret redaction/hashed argv, auth observers, owner
fingerprints, credential-chain changes, responsive navigation, and harness
oracle tightening.

**Acceptance:** focused SDK/config/binding/appdb/graph/API/ingest tests under
`-race`; Go format/build/vet; UI Scan Manager/Import tests; Compose rendering;
strict docs; live fresh/restart/mismatch/cross-wire/no-mutation controls across
Neo4j 4.4 and 5.x.

### 02 — `codex/release-stack-02-collector-truth`

**Parent:** stack 01.

**Purpose:** make collector artifacts deterministic, closed, bounded, and
secret-safe before the server reasons over them.

**Issues:** RC-03 Issues 3, 4, 24, 25, 27, 28, 31; RC-04 Issues 23, 26, 29,
30; RC-06 Issues 8 and 13.

**Owns:**

- Raw MCP Initialize observation, tasks capability, absent resource-size
  semantics, alias/profile determinism, case-normalized headers, bounded
  streamable HTTP, and zero-network ambiguity controls.
- Sanitized HTTP endpoints, stdio hashed-argv identity v3, credential extraction,
  fixed diagnostic categories, and matching strict-ingest privacy checks.
- Canonical Config `Identity`/`Credential` producer topology, strict
  configured/observed authentication tuple validation, and MCP opaque-header
  authentication truth required by those same privacy-boundary hunks.
- Canonical embedding source IDs and reference-only endpoint closure.
- Collector-focused tests and corresponding CLI/graph/security documentation.

**Must exclude:** effective-auth analysis, A2A runtime auth probing, graph
fingerprint lifecycle, credential blast radius, and unrelated responsive UI.

**Acceptance:** collector/SDK/Config/MCP/A2A/embedding/mcppoison/strict-ingest
race suites; enforcing real MCP credential gate; alias reversal/repetition;
timeout control; whole-envelope/stderr sentinel scans; strict importer negative
matrix.

### 03 — `codex/release-stack-03-graph-lifecycle-cli`

**Parent:** stack 02.

**Purpose:** make publication lifecycle and CLI outcome reporting truthful
before downstream analysis is changed.

**Issues:** RC-05 Issues 6, 21, 22 and integration Issues 12, 20; RC-06
integration Issue 10; RC-07 Issues 7, 14 and functional part of integration
Issue 19.

**Owns:**

- Owner-scoped semantic fingerprints, deterministic writer preparation,
  coherent public-fact preservation, exact owner transfer, and atomic
  `all_dependencies` group rotation.
- Schema-2 legacy/future-version admission boundary.
- Structured-reader removal of internal fingerprints.
- Typed CLI ingest results, partial diagnostics, causal errors, and checked
  output writes.
- Graph/ingest/CLI tests and matching graph/deployment/API documentation.

**Must exclude:** authentication scoring/queries, credential-chain grouping,
responsive UI, and test-harness completeness changes.

**Acceptance:** full graph/ingest/CLI race suites; Neo4j 4.4 fallback, Neo4j 4.4
APOC, and Neo4j 5 lifecycle matrix; structured API secret/internal-property
scan; unpublished/partial/output-writer CLI controls.

### 04 — `codex/release-stack-04-auth-evidence`

**Parent:** stack 03.

**Purpose:** preserve configured versus observed authentication provenance and
make every consumer use a complete effective tuple.

**Issues:** RC-02 Issues 2, 9, 15, 16, 35, 40, 44, 45, 46; candidate hardening
Issues 43 and 41; RC-10 Issue 36; credential-to-resource portion of RC-09
Issue 32.

**Owns:**

- Open WebUI fingerprint/loot composition.
- Bounded official-protocol A2A nonexistent-task observer and its strict
  positive/diagnostic evidence validation.
- Ollama/MLflow/Qdrant proof-before-affirmation and empty-credential rejection.
- Effective-auth materialization and all query/risk/traversal/remediation/UI
  consumers.
- The complete `CanReach` effective-auth gate and canonical
  Server→Identity→Credential resource witness, which are one Cypher unit.
- Evidence drawer and Markdown provenance representation.
- Focused real controls and relevant auth documentation.

**Must exclude:** cross-service credential grouping/risk changes not required by
effective auth, responsive navigation/dialog geometry, and general harness
oracle completeness.

**Acceptance:** producer/validator/analysis/UI race and component suites;
official A2A v1/v0.3 positive/protected/inconclusive controls with zero mutation;
custom-header MCP gate; protected and public looter controls; live effective-auth
Neo4j/query/risk projection.

### 05 — `codex/release-stack-05-credential-analysis`

**Parent:** stack 04.

**Purpose:** correct credential topology, attribution, witness determinism,
blast radius, and downstream risk/query results.

**Issues:** remaining cross-service portion of RC-09 Issue 32, plus Issues 33
and 37; post-checkpoint composition findings S5-F1 and S5-F2.

**Owns:**

- Cross-service Config credential → canonical value-hash group → LiteLLM
  gateway/upstream-credential correlation over the producer topology
  established in stack 02.
- Exact observed-material/value-hash gates and identity-hash exclusion.
- Deterministic seven-node/five-relationship plus synthetic witness.
- Global distinct-agent blast radius at canonical value-hash grain.
- High-entropy attribution and risk-score consumers.
- Credential campaign/query tests and credential-chain/risk documentation.

**Acceptance:** processors/prebuilt/riskscore race suites; isolated one-agent,
two-agent, duplicate-path, identity-only, masked, and non-high-entropy Neo4j
matrix; exact three-target public/persisted/live evidence reconciliation.

### 06 — `codex/release-stack-06-ui-docs-oracles`

**Parent:** stack 05.

**Purpose:** finish independent presentation/documentation corrections and make
the release harness incapable of false-green completeness claims.

**Issues:** remaining RC-10 Issues 5 and 11; RC-11 Issues 17, 34, 42; RC-12
Issues 38 and 39.

**Owns:**

- Viewport-bounded dialogs, accessible compact navigation, and scrollable lens
  controls.
- Extraction-field, credential-chain topology, and 23/20/12 cardinality docs.
- Exact 24-record harness reconciliation and exact three-target cross-service
  oracle, including a non-null truthful `via_gateway` value.
- Remaining real-infrastructure fixtures/gates and final validation ledger.

**Acceptance:** full UI tests/lint/build; baseline/candidate narrow and desktop
browser matrix; strict MkDocs and stale-claim searches; mutated-oracle matrix;
one fresh exact 24-scenario run; database/API/browser reconciliation; final
`make prerelease`.

## Shared-file handling

The following files require hunk-level staging and a named owner per hunk. They
must never be copied wholesale into an early slice:

- `CHANGELOG.md`, `README.md`, `Makefile`
- `collector/cli/{campaign,discover,extract,loot,root,scan}.go`
- `modules/{a2a,config,mcp}/collector.go` and their large test files
- `sdk/ingest/{ids,ingest,model_test,metadata}.go`
- `server/cli/bootstrap.go`
- `server/internal/graph/integration_test.go`
- `server/internal/ingest/{pipeline,validator}.go` and tests
- `server/internal/api/handlers/openapi.yaml`
- `server/ui/src/__tests__/ScanManager.test.tsx`
- `test-infra/{docker-compose.yml,run-tests.sh}`
- `docs/architecture/{ingest-pipeline,post-processors,system-design}.md`
- `docs/operator/{deployment,security}.md`
- `docs/reference/{api,cli,configuration,graph-model,risk-scoring}.md`

Each stack commit records a path/hunk manifest. The final stack is accepted only
when:

1. every parent branch passes its stated gates;
2. `git diff 6428f13 --` contains only the exact reviewed post-checkpoint
   corrections documented above;
3. the validation documents remain on the separate snapshot branch rather than
   entering product PRs accidentally; and
4. unrelated untracked `AGENTS.md` is absent from every commit.

## Construction procedure

1. Create an isolated split worktree and branch from product checkpoint
   `6428f13`.
2. Mixed-reset that isolated branch to baseline `1e45601`; this leaves the exact
   candidate tree as unstaged changes without touching the primary worktree.
3. Stage exclusive files plus reviewed shared hunks for stack 01, run its gates,
   and commit.
4. Repeat for stacks 02–06. Every commit is reviewed as the diff from its parent.
5. Prove the final split tree differs from `6428f13` only by the exact reviewed
   post-checkpoint corrections documented above.
6. Create branch refs at each commit. Do not push until explicitly authorized.

This procedure changes only isolated Git index/branch state. It does not modify
the validated snapshot branch, the retained release databases, or the public
remote.

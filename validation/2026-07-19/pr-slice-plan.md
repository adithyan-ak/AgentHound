# AgentHound v1.0 Candidate Review Stack

## Objective

Convert the validated 221-file candidate checkpoint into reviewable changes
without losing cross-component invariants or pretending coupled fixes are
independent. The stack is constructed from the untouched baseline
`1e45601c4d004247da60c0f0e796debfb3cc37fc`; its final tree must be byte-equal
to product checkpoint `6428f13` for every tracked product file.

The configured `origin` is public. No review branch is pushed until the user
explicitly authorizes the exact branch and remote.

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

**Issues:** RC-08 / Issue 18, plus candidate-integration Issue 47 because the UI
must not advertise commands that cannot create v3 artifacts.

**Owns:**

- `sdk/ingest/origin.go`, origin metadata, and v2→v3 wire version.
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
strict docs; live fresh/restart/mismatch/cross-wire/no-mutation matrix on Neo4j
4.4 and 5.x.

### 02 — `codex/release-stack-02-collector-truth`

**Parent:** stack 01.

**Purpose:** make collector artifacts deterministic, closed, bounded, and
secret-safe before the server reasons over them.

**Issues:** RC-01; RC-03 Issues 3, 4, 24, 25, 27, 28, 31; RC-04 Issues 23,
26, 29, 30; RC-06 Issues 8 and 13.

**Owns:**

- Release-version single-writer behavior.
- Raw MCP Initialize observation, tasks capability, absent resource-size
  semantics, alias/profile determinism, case-normalized headers, bounded
  streamable HTTP, and zero-network ambiguity controls.
- Sanitized HTTP endpoints, stdio hashed-argv identity v3, credential extraction,
  fixed diagnostic categories, and matching strict-ingest privacy checks.
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
Issues 43 and 41; RC-10 Issue 36.

**Owns:**

- Open WebUI fingerprint/loot composition.
- MCP custom-header/credential observation truth.
- Bounded official-protocol A2A nonexistent-task observer and strict evidence
  validation.
- Ollama/MLflow/Qdrant proof-before-affirmation and empty-credential rejection.
- Effective-auth materialization and all query/risk/traversal/remediation/UI
  consumers.
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

**Issues:** RC-09 Issues 32, 33, and 37.

**Owns:**

- Location-independent Agent→Server→Identity→Credential reachability.
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
  oracle.
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
2. `git diff 6428f13 --` is empty for product files at stack 06;
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
5. Prove the final split tree is product-byte-equal to `6428f13`.
6. Create branch refs at each commit. Do not push until explicitly authorized.

This procedure changes only isolated Git index/branch state. It does not modify
the validated snapshot branch, the retained release databases, or the public
remote.

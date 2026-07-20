# PR 98 independent-review follow-up

Date: 2026-07-19 PDT

PR: [#98 — Preserve owner-scoped graph publication truth](https://github.com/adithyan-ak/AgentHound/pull/98)

Reviewed snapshot supplied by the independent reviewer:

- base `acad077295b0e2de455fd67c237df13666f34a55`
- head `2084a632eaf93ff362d2b61b4c89ef1d332a578f`

Live PR snapshot at adjudication start:

- base `6171b8eccf9c9d82935c931c43c887d1d5e9cb34`
- head `a1890607d390d8d662594d88f945ef17a011a0ab`

Corrected PR head:

- `d2590ed441449a234de30ba2d819ab5be80b6d87`

The distinction matters because the live head already contained an A2A
contribution-preservation correction added during the PR 97 follow-up/restack.
Every review claim was therefore checked against both the supplied snapshot
and the current PR rather than applying stale line-number advice directly.

## Adjudication

| Claim | Verdict | Action |
|---|---|---|
| Audit issues 6, 21, and 22 are genuine lifecycle defects | Confirmed | No additional implementation change. The existing per-owner fingerprints, exact-transfer proof, and atomic dependency-group replacement address them. |
| Audit issue 12 / A2A owner contributions collapse before fingerprinting | Confirmed on old head `2084a63`; already fixed on live head `a189060` | No second production rewrite. Strengthened `TestCollectorPreservesSharedAgentPerTargetDomain` with the reviewer's exact two-target/same-canonical-URL/different-properties case. It proves one logical ID retains two distinct owner contributions. |
| Audit issue 20 schema-1 admission gap | Confirmed | No change. Explicit schema-2 admission and reset/recollection policy remain correct for the unreleased development schema. |
| Audit issue 10 structured analysis responses expose internal fingerprints | Confirmed on live head | Fixed at the existing `graph.PublicFactProperties` boundary for traversal rows, exact finding capture before PostgreSQL persistence, and finding-detail rendering of older persisted evidence. Raw Cypher remains intentionally raw. Added non-mutation and negative disclosure tests. |
| Audit issues 7 and 14 CLI success/diagnostic defects | Confirmed | No additional change. Existing typed result rendering and nonzero unpublished outcome behavior remain correct. |
| Audit issue 19 is a reproducible baseline product defect | Rejected | `golangci-lint` reports zero issues at the reviewed endpoints and `coalesceObservationGraph` was active in the base pipeline. Any lint cleanup during patch construction is implementation hygiene, not an independently validated product issue. PR wording was corrected accordingly. |
| Graph-model documentation still promises last-write-wins | Confirmed | Replaced the stale statement with the implemented per-owner compatible-union, conflict-rejection, reference-only, exact-replacement, and atomic dependency-group rules. |

## Structured-boundary correction

Internal `observation_fact_fingerprints` now remain available only inside Neo4j
and the intentionally raw Cypher operator surface. The following structured
paths use a cloned and sanitized property map:

- traversal selector and adjacency nodes used by shortest-path responses;
- detector-selected exact finding nodes and relationships before persistence;
- attack-path rendering from persisted exact evidence, including older rows
  that may predate the capture-time correction.

The sanitizer does not mutate the Neo4j query row or persisted finding model.

## Validation

Passed on corrected PR 98 head:

- `go test ./modules/a2a ./server/internal/analysis -race -count=10`
- `golangci-lint run ./...` — zero issues
- strict `make docs-check` in a fresh virtual environment installed only from
  `docs/requirements.txt`
- `gofmt -l .` — no output
- `go build ./...`
- `go vet ./...`
- `go test ./... -race`
- `git diff --check`

The enhanced A2A regression uses two valid cards from different requested
targets, gives both cards the same advertised canonical URL, assigns different
names/descriptions, and asserts that the artifact retains the correct property
set under each target's single observation domain.

The analysis regressions inject internal fingerprints into traversal rows and
exact finding evidence, assert absence from structured results, and assert that
the original raw maps remain unchanged.

## Inherited opt-in integration fixture gap

The independent reviewer reported strict-v3 failures in the opt-in fresh
database ingest suite. A new run against dedicated Neo4j 5.26.28 and PostgreSQL
16 containers reproduced four failures on the current PR 98 head:

- `TestIntegrationCompiledCampaignExportProbeIngestPromotesOnlySourceAgent`
- `TestIntegrationFreshSchemaCompleteIngestPublishes`
- `TestIntegrationExhaustiveRootRemovesMissingChildAcrossGraphAndPublication`
- `TestIntegrationTokenlessAgentWithholdsPublication`

The affected fixture files are unchanged between PR 98's current base and
head. This is inherited strict-v3 test-fixture drift, not a regression in the
Stack 3 lifecycle implementation. It belongs to the strict-ingest producer
boundary in PR 97 and was not hidden inside PR 98. The dedicated containers
were removed after the run and no volumes were created.

Until that separate fixture maintenance is completed, PR 98 does not claim
that the repository-wide opt-in `AGENTHOUND_FRESH_DB_INTEGRATION=1` ingest
suite passes. Its focused Neo4j lifecycle matrix and mandatory repository
checks remain independently green.

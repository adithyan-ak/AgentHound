# AgentHound Candidate Root-Cause Validation Index

## Purpose

This document reduces the 47 numbered entries in the final-test ledger into the smallest defensible set of independently reviewable root causes. It is a triage artifact, not an assertion that every patch is accepted.

The next validation stage must prove each product root cause against the untouched baseline and the checkpointed candidate using the same input and appropriate negative controls.

That stage is now complete. See `root-cause-verdicts.md` for the independent
before/after verdicts. Its final accounting supersedes this index's provisional
classification while preserving the same exact issue-to-group mapping.

## Frozen inputs

- Untouched baseline commit: `1e45601c4d004247da60c0f0e796debfb3cc37fc`
- Candidate checkpoint commit: `6428f13` (`chore(validation): checkpoint final-test candidate`)
- Local checkpoint branch: `codex/validation-snapshot-20260719`
- Candidate checkpoint scope: 221 tracked files; unrelated untracked `AGENTS.md` excluded
- Detailed ledger: `test-infra/artifacts/release-validation-working/ledger.md`
- Ledger SHA-256 at checkpoint: `79af35b8e6216efb685a1159ef70aaf2b043040636871080045d39b00514f3de`
- Configured GitHub repository: `adithyan-ak/AgentHound`, visibility `PUBLIC`
- Cloud status: intentionally not pushed; an unreviewed candidate and synthetic secret fixtures must not be published as a backup

## Classification summary

The ledger contains 47 numbered issues, but they are not 47 independent root causes:

- 35 entries are confirmed baseline product-defect records.
- 7 entries are valid candidate-integration or hardening corrections introduced
  while composing the temporary fixes: Issues 10, 12, 19, 20, 41, 43, and 47.
- 3 entries are documentation-only contract defects: Issues 17, 34, and 42.
- 2 entries are validation-oracle defects where the current product was not shown to be wrong: Issues 38 and 39.
- Several additional unnumbered entries document invalid/contained test attempts or test-infrastructure corrections. They are excluded from the product-defect count.
- The 47 numbered entries map exactly once into 12 confirmed root-cause groups below.

The 35 baseline product records are symptoms or boundary cases within ten
product root-cause groups; they are not 35 independent bugs. The seven
candidate-integration corrections are real and necessary, but must not be
marketed as defects independently reproduced in the untouched baseline.

## Root-cause groups

| ID | Root cause | Issues | Class | Priority | Independent acceptance proof |
|---|---|---:|---|---|---|
| RC-01 | Release-version provenance had multiple writers | 1 | Product | P1 | Build one binary with an injected sentinel version; every artifact-producing verb must report that exact version on candidate and at least one must demonstrate the stale override on baseline. |
| RC-02 | Authentication and observation claims were not consistently evidence-backed | 2, 9, 15, 16, 35, 40, 43, 44, 45, 46 | Product/security semantics | P0 | Use protected, anonymous, custom-header, query-credential, malformed, and wrong-shape controls. Baseline must reproduce each claimed false positive/false negative class; candidate must emit only complete provenance-paired evidence. Pinned real-service checks are required for Open WebUI, MCP, A2A, and the three affected looters. |
| RC-03 | MCP/A2A protocol collection lost information, selected aliases nondeterministically, or escaped bounds | 3, 4, 24, 25, 27, 28, 31 | Product/interoperability | P1 | Replay raw protocol controls across streamable HTTP, SSE, stdio, and A2A aliases. Require request witnesses, deterministic results under reversed input order, zero network calls on ambiguity, exact timeout bounds, and preservation of supported capability/resource semantics. |
| RC-04 | Credential-bearing transport material crossed artifact, log, diagnostic, or ingest trust boundaries | 23, 26, 29, 30 | Product/security/privacy | P0 | Whole-envelope sentinel reproduction on baseline; candidate must retain credentials only in memory for transport while excluding them from JSON, stderr, receipts, APIs, and graph properties. Crafted imports and rejected paths must cause zero graph/database mutation. |
| RC-05 | Multi-owner graph facts lacked safe semantic identity and lifecycle transitions | 6, 12, 20, 21, 22 | Product/data integrity | P0 | Run the same owner-refresh/transfer/retirement matrix against baseline and candidate on Neo4j 4.4 fallback, Neo4j 4.4 with APOC, and Neo4j 5.x. Candidate must preserve the last coherent public fact, rotate owners atomically, reject semantic conflicts, and handle legacy/future schemas without mutation. |
| RC-06 | Graph identities, endpoint closure, and public/internal property boundaries were inconsistent | 8, 10, 13 | Product/data/API integrity | P1 | Strict-ingest baseline/candidate comparison must prove endpoint closure and canonical IDs without fabrication. Enumerate every structured graph/finding/traversal/export response and prove internal fingerprints are absent while raw Cypher remains intentionally raw. |
| RC-07 | CLI success and diagnostic behavior could contradict pipeline/output failure | 7, 14, 19 | Product/CLI reliability | P1 | Inject unpublished results, partial committed writes, underlying pipeline errors, and a failing output writer. Baseline must demonstrate false success or lost diagnostics; candidate must print the typed result, preserve the causal error, and exit nonzero. |
| RC-08 | Host-local and private-network evidence shared global identity/lifecycle without storage admission | 18 | Product architecture/release blocker | P0 | Reproduce Host A → Host B destructive replacement on baseline. On candidate, exercise fresh binding, restart, wrong host/realm, crossed PostgreSQL/Neo4j pairs, future marker versions, one-sided empty recovery, nonempty legacy state, and runtime marker tampering on Neo4j 4.4 and 5.x. Every rejected case must be mutation-free. |
| RC-09 | Credential correlation, reachability, attribution, and risk used stale topology or grouping | 32, 33, 37 | Product/analysis correctness | P0 | Use header, argv, URL, env, same-hash multi-credential, identity-only, masked, and non-high-entropy controls. Baseline must reproduce missing/wrong reachability or scores; candidate must produce deterministic exact evidence, global distinct-agent blast radius, and independently calculated risk/query results. |
| RC-10 | Frontend controls or evidence representation contradicted live product state | 5, 11, 36, 41, 47 | Product/UI | P2 | Rebuild both trees, compare API payloads to browser-visible state at narrow and desktop viewports, exercise dialog/navigation/lens controls, inspect MCP/A2A evidence banners, and copy every advertised scan command. Candidate commands must execute the collector contract. |
| RC-11 | Public documentation described graph fields/topology/cardinalities that do not exist | 17, 34, 42 | Documentation-only | P3 | Compare each statement directly with the relevant producer/kind registry/query, then run strict MkDocs. No runtime baseline campaign is required. |
| RC-12 | The release harness/oracles could declare incomplete coverage green | 38, 39 | Validation infrastructure | P0 methodology | Mutate the result set and cross-service projection: missing, duplicate, unexpected, malformed, counter mismatch, and one-of-three target cases must all be rejected. Prove the exact valid 24-record set remains green. This validates the test system, not a product patch. |

## Exact issue-to-group mapping

This list prevents an issue from being lost or counted in multiple root causes.

- RC-01: 1
- RC-02: 2, 9, 15, 16, 35, 40, 43, 44, 45, 46
- RC-03: 3, 4, 24, 25, 27, 28, 31
- RC-04: 23, 26, 29, 30
- RC-05: 6, 12, 20, 21, 22
- RC-06: 8, 10, 13
- RC-07: 7, 14, 19
- RC-08: 18
- RC-09: 32, 33, 37
- RC-10: 5, 11, 36, 41, 47
- RC-11: 17, 34, 42
- RC-12: 38, 39

## Unnumbered validation-infrastructure notes

These entries remain useful forensic history but must not be presented as product bugs:

- Incorrect integration-test wrapper/cleanup ordering during the graph-schema matrix.
- Generated Go toolchain/cache state under the isolated fixture `HOME`.
- The first real credential-bearing MCP lane lacked an enforcing upstream gate.
- The first credential-gate proxy buffered standalone SSE response headers.
- Bash 3.2 expanded an empty optional Compose array incompatibly under `set -u`.
- Docker Desktop's configured credential helper blocked pinned-image metadata while an empty client configuration worked against the same daemon.
- Interrupted or harness-invalid run directories explicitly marked non-evidence.

These corrections should be reviewed with RC-12 and kept separate from product-fix PR claims.

## Fast validation order

The optimal order maximizes early confidence and avoids spending time on UI/docs over an invalid security or lifecycle premise.

### Wave 1 — establish that the evidence system and safety boundaries are trustworthy

1. RC-12 harness/oracle integrity
2. RC-08 collection realm and storage binding
3. RC-04 credential/privacy boundaries
4. RC-02 authentication evidence truth
5. RC-05 graph lifecycle ownership

### Wave 2 — validate functional and analytical correctness

1. RC-03 protocol collection
2. RC-09 credential reachability/risk
3. RC-06 graph/API integrity
4. RC-07 CLI truth
5. RC-01 version provenance

### Wave 3 — validate representation and documentation

1. RC-10 frontend
2. RC-11 documentation

After all 12 groups have an accepted verdict, run one integrated fresh 24-scenario harness, database/API/browser reconciliation, and `make prerelease`. Do not rerun the complete harness after every root cause.

## Required verdict record

Each group receives one short record:

```text
Root cause:
Baseline command/tree:
Baseline result and exact failure reason:
Candidate command/tree:
Candidate result:
Negative controls:
Real upstream/database/browser proof, or why not required:
Patch scope reviewed:
Verdict: CONFIRMED / PARTIAL / REJECTED / NEEDS REVIEW
Reviewer:
Evidence paths and hashes:
```

No product change should enter a PR solely because the candidate tests pass. A `CONFIRMED` verdict requires the baseline defect, candidate correction, and negative controls to all be demonstrated.

## Cloud-backup decision

Do not push this checkpoint to the configured public `origin` merely for storage. Preferred options, in order:

1. A private repository or private backup remote with restricted membership and branch protection disabled only as needed for the snapshot.
2. Encrypted object storage containing a `git bundle` plus its SHA-256.
3. The current local branch plus a second local/off-host encrypted bundle until the validation waves reduce the candidate to reviewable PRs.

Before any cloud copy, run a secret scanner over the full candidate commit and manually review every intentional synthetic-secret fixture. Public pull requests should be created only from independently accepted root-cause slices, never from this snapshot branch.

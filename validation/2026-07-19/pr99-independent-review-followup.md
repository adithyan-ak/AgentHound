# PR 99 independent-review follow-up

Date: 2026-07-19 PDT

PR: [#99 — Require observed authentication evidence across consumers](https://github.com/adithyan-ak/AgentHound/pull/99)

Reviewed snapshot supplied by the independent reviewer:

- base `2084a632eaf93ff362d2b61b4c89ef1d332a578f`
- head `e6a6af7784296dd76397698f0169991a5132993e`

Live PR snapshot at adjudication start:

- base `a1890607d390d8d662594d88f945ef17a011a0ab`
- head `5f34f4c5fb48b8cdfeeca3878c57a6d9f7a4a5ad`

Corrected and initially restacked product heads:

- PR 98 / Stack 3: `d2590ed441449a234de30ba2d819ab5be80b6d87`
- PR 99 / Stack 4: `14c29f13038378d59dbe471f398d5f84b0b68d91`
- PR 100 / Stack 5: `bb7c0b191c8f31153783cd2365593b24dd7c5eae`
- PR 101 / Stack 6: `ff7a95b87923ae6542d596e7545ab3d2d0b8b53d`

A later content-preserving stack restack produced the current remote heads:

- PR 98 / Stack 3: `090f763238f870c12a83a17d74e689f1878f1f61`
- PR 99 / Stack 4: `2872fdbf0dda5cd20afa43ad42cce650a467c6f8`
- PR 100 / Stack 5: `9c2904c3b7d1f3a0795c751c63bdc29d46a82e59`
- PR 101 / Stack 6: `8af65f1c950b8e960ec5df8f7f32be5ce0978ef9`

The fully validated pre-restack Stack 6 head `9b63d181ca52d364a99a38cf4c200f8517ca59ae`
and current remote head `8af65f1c950b8e960ec5df8f7f32be5ce0978ef9`
have the identical Git tree
`cdd8cfb4809592b8d57c62198b2d2584f57c172a`; no validation result was
carried across a content change.

The live Stack 3 base changed concurrently during adjudication because the PR
98 review added its structured-fingerprint-boundary correction. The PR 99
auth commit and this follow-up were replayed onto that base without changing
their content. Every recommendation was evaluated against both the supplied
historical range and the live PR range before publication.

## Adjudication

| Review claim | Verdict | Disposition |
|---|---|---|
| Issue 2: Open WebUI public identity probes fabricated anonymous privileged access | Confirmed | No additional change. The public fingerprint now proves identity only and omits auth posture. |
| Issue 9: Open WebUI configuration references conflicted with directly probed Ollama provenance | Confirmed | No additional change. Configuration-only backends remain references; active discovery/probe properties belong to the direct producer. |
| Issue 15: Open WebUI fingerprinter and looter could publish mutually exclusive auth facts | Confirmed | No additional change. Identity-only fingerprinting and looter-owned observed auth now compose. |
| Issue 16: auth/provenance and timestamp conflicts all belong to PR 99 | Partially confirmed | PR 99 fixes authentication and active-discovery provenance. Stack 3 already treats `last_verified_at` as volatile and deterministically selects the latest valid RFC3339 value. PR wording was corrected. |
| Issue 35: consumers mixed configured and observed auth fields | Confirmed | No additional change. Effective tuples are selected atomically and consumed across analysis, risk, traversal, remediation, API, and UI paths. |
| Issue 40: the A2A no-auth detection had no supported runtime producer | Confirmed | No additional change. The bounded nonexistent-task lookup supplies exact positive or diagnostic evidence. |
| Issue 44: opaque MCP headers were still a defect on PR 99's base | Rejected for this PR's scope | Stack 2 already classifies every nonempty opaque configured header as `unknown/configured_credential`; focused base tests passed. PR 99 consumes that invariant but does not claim to implement it. |
| Issue 45: looters published anonymous/verified posture before successful inventory | Confirmed | No additional change. Ollama, MLflow, and Qdrant promote affirmative posture only after canonical inventory succeeds. |
| Issue 46: all empty-material paths were closed | Partially confirmed; one material omission reproduced | LiteLLM accepted a whitespace-only `master_key`, emitted an observed/exposed master Credential, and returned success with two partial failures. Fixed before graph construction or network activity, with a regression requiring an error, nil result, and zero requests. |
| Issue 43: the base performed a credential-bearing operational auth probe | Rejected as a base claim; accepted as candidate hardening | The base fetched Agent Cards but had no operational probe. The new credential-free observer correctly refuses query-bearing advertised interfaces so it cannot forward query credentials or mislabel that request anonymous. PR wording was corrected. |
| Issue 41: the base Evidence drawer omitted evidence that did not yet exist | Rejected as an independent base defect; accepted as required integration | The new producer requires the UI to expose its exact method/status/detail tuple. PR wording now states that dependency. |
| Issue 36: Explorer unconditionally called unknown nodes verified | Rejected as stated; dependent symptom confirmed | The base UI already rendered missing evidence as unknown. False looter `probe_status=verified` values caused “Directly verified.” Producer truth is the material fix; evidence-aware rendering remains correct. |
| Issue 32 auth portion: `CAN_REACH` required only legacy `HAS_ENV_VAR` topology | Confirmed | No additional change. The processor consumes canonical Identity/Credential topology for observed material across supported transports. |

No additional functional defect was found behind the five scope/wording
qualifications. They resulted in a more accurate PR description, not extra
production abstractions or operator options.

## LiteLLM reproduction and correction

The first regression run on the live PR head failed as follows:

```text
WARN ... /model/info ... invalid header field value for "Authorization"
WARN ... /key/list ... invalid header field value for "Authorization"
INFO ... credentials_found=1 partial_failures=2
--- FAIL: TestLoot_RejectsWhitespaceOnlyMasterKeyBeforeProbing
    expected error for whitespace-only master_key
```

The looter checked only `masterKey == ""`. Whitespace therefore received a
nonempty SHA-256 value hash, `material_status=observed`,
`exposure_status=exposed`, and an `EXPOSES_CREDENTIAL` edge before either
request failed. Those facts satisfy the critical observed LiteLLM master-key
exposure query despite no usable credential observation.

The correction checks `strings.TrimSpace(masterKey) == ""` only as a validity
predicate. It does not assign the trimmed value, so every byte of a nonblank
credential remains the identity/transport material. No CLI argument or
operator workflow changes.

## A2A source validation

The current official A2A specification defines v1 `GetTask` as retrieval of an
existing task and `TaskNotFoundError` as the missing/inaccessible result:

- <https://a2a-protocol.org/latest/specification/>

The official v0.3 specification defines the corresponding JSON-RPC method as
`tasks/get`:

- <https://a2a-protocol.org/v0.3.0/specification/>

The implementation selects those version-appropriate names, uses a random
nonexistent task ID, sends no credential headers/userinfo/query bytes, forbids
redirects and cross-origin expansion, bounds time/response size, and accepts
only the exact version-appropriate task-not-found response as positive
evidence. All other outcomes remain diagnostic/inconclusive.

The checked-in real-infrastructure service is pinned to official
`a2a-sdk[http-server]==1.1.0`. Earlier release-validation evidence instrumented
SDK-side executor/store counters, but that instrumentation is not checked into
PR 99. The PR description was corrected to distinguish reproducible PR-local
request/evidence controls from that retained supporting evidence.

## Validation

Passed on corrected PR 99 head:

- focused pre-fix regression: failed with one fabricated Credential and two
  partial request failures, establishing bug presence;
- focused post-fix LiteLLM regression and full module race suite;
- `gofmt -l .` — no output;
- `go build ./...`;
- `go vet ./...`;
- full `go test ./... -race`;
- UI dependency install from `package-lock.json`, 50 files / 229 tests, lint,
  and production build;
- strict `make docs-check` in a fresh temporary environment installed from
  `docs/requirements.txt`; and
- `git diff --check`.

After restacking PRs 100 and 101, the exact final candidate
`ff7a95b87923ae6542d596e7545ab3d2d0b8b53d` passed all 13
`make prerelease` gates. Collector linux/amd64 size was 11,051,192 bytes
against the 12,012,132-byte limit.

The existing PR 101 worktree contained unrelated uncommitted changes in
`test-infra/README.md` and `test-infra/lib/assert-cross-service-chain.sh`.
They were not stashed, modified, included, or discarded. PR 101 was restacked
from its prior committed head in an isolated detached worktree and pushed with
an exact force-with-lease guard.

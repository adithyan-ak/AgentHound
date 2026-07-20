# PR 97 independent-review follow-up

## Scope and decision

This record evaluates the two material recommendations from the independent
review of PR 97 without presuming either recommendation was correct.

The reviewer compared `ee070b70d722d8c840517992f2d08017e8361957` to
`acad077295b0e2de455fd67c237df13666f34a55`. At follow-up time, the live PR
compared `4d61d0fcf8327a02a64f24d05dc4f20cd98baa5d` to
`0ced50754f8ad856705137ff9e7f9990e27ace91`. The old and current PR 97 trees
have identical `modules/a2a` and relevant MCP enumeration code; the rewritten
commits between those snapshots only adjusted Stack 1 database migration/test
composition. Both findings therefore remained applicable to the live PR.

Final dispositions:

| Finding | Validity | Disposition |
|---|---|---|
| A2A relationship ownership is alias-order dependent | Confirmed material true positive | The code defect is fixed in Stack 3 / PR 98, where the required atomic `all_dependencies` lifecycle primitive and its live graph controls are independently reviewable. PR 97 must no longer claim this closure. |
| Streamable MCP session `DELETE` can outlive the per-server timeout | Confirmed material true positive | Fixed in Stack 2 / PR 97 by carrying the existing absolute per-server deadline into SDK-owned HTTP lifecycle requests. No CLI option was added. |

The final rebased product stack is `3fac021067c4f3c76c4ba80164271de057f202eb`.
Compared with the previously accepted Stack 6 tree
`1d497323ed528814b5e7122218332cf01f799b35`, its only content delta is the
three-file MCP deadline patch and regression. Moving A2A ownership from Stack 4
to Stack 3 changes review ownership, not the assembled product tree.

## Finding 1 — A2A alias ownership

### Independent reproduction

PR 97 contained no A2A delta despite claiming Audit issue 25:

```text
git diff --name-only 4d61d0f..0ced507 -- modules/a2a
<no output>
```

The production collector used `map[string]string` for `agentScopes` and assigned
`agentScopes[agentNodeID(card)] = scopeKey`. Two requested endpoints returning
the same canonical card therefore overwrote one another. Both
`DELEGATES_TO` and `SAME_AUTH_DOMAIN` received only the last target scope.

An exact production-path HTTP test used two aliases for Agent Alpha and two for
Agent Beta. Before the patch, its expected dependency-group assertion failed:

```text
DELEGATES_TO dependency group = [one-alpha-scope one-beta-scope]
want [both-alpha-scopes both-beta-scopes]
```

Reversing the targets selected the other alias. A separate temporary
bug-presence reproduction repeated the forward/reverse behavior 10/10 times.

### Product decision and rejected recommendation

The reviewer's diagnosis is valid, but its suggested source/target Cartesian
pairing is not AgentHound's ownership model. Audit issues 22 and 25 deliberately
define one indivisible `all_dependencies` group per logical relationship.
Alternative dependency groups for one source/kind/target are rejected because
the writer cannot publish several mutually competing semantic owner sets for
one raw relationship.

The accepted representation is one sorted union of all successful endpoint
scopes. A complete incoming group atomically replaces the prior group. A partial
incoming group cannot replace the last coherent published relationship. This
keeps relationship identity stable, preserves every successful alias, and
avoids introducing nested dependency-group schema solely for this case.

### Correct placement and implementation

The A2A producer correction was moved from Stack 4 into Stack 3 because Stack 3
owns the matching atomic dependency-group rotation. This makes the issue and
its complete solution independently reviewable in PR 98.

Stack 3 now:

- sorts collection results by canonical coverage scope;
- retains all successful scopes per canonical agent;
- preserves one node/edge contribution per observation domain until writer
  conflict validation;
- emits one sorted, indivisible relationship dependency group;
- removes duplicate delegation evidence;
- canonicalizes the symmetric `SAME_AUTH_DOMAIN` direction;
- excludes failed aliases from the fresh affirmative group; and
- retains conflicting fragments for deterministic fail-closed writer
  validation instead of hiding them with last-write-wins deduplication.

The implementation does not add flags or operator workflow.

### Negative controls

`TestCollectorSharedAgentAliasesAreOrderIndependentAndLifecycleSafe` proves:

- forward/reverse target order is byte-equivalent after volatile timestamps are
  removed;
- two aliases on both endpoints yield one `DELEGATES_TO` and one
  `SAME_AUTH_DOMAIN`, each with all four scopes;
- endpoint direction is canonical;
- a failed alias is reported failed, makes the collection partial, and is absent
  from the new affirmative group; and
- every relationship domain belongs to a completed outcome.

Additional tests require separate per-target agent contributions and prevent
the collector's deduplication layer from concealing distinct same-owner
fragments. Existing Stack 3 graph tests prove complete owner-set rotation,
idempotence, partial-group preservation, recovery, and stale dependency
retirement in both fallback and APOC writer implementations; the live matrix
previously passed Neo4j 4.4 and 5.x.

Focused result:

```text
go test ./modules/a2a -run '^(TestCollectorSharedAgentAliasesAreOrderIndependentAndLifecycleSafe|TestCollectorPreservesSharedAgentPerTargetDomain|TestA2AContributionDedupPreservesDistinctSameOwnerFragments|TestSetRelationObservationScopesUsesAnyOwnerForSameScope)$' -count=10 -v
PASS

go test -race ./modules/a2a ./server/internal/graph -count=1
PASS
```

## Finding 2 — MCP cleanup timeout

### Independent reproduction

The controlling dependency is the repository-pinned
`github.com/modelcontextprotocol/go-sdk v1.6.1`; its exact checked-out source is
more authoritative for this defect than behavior in an unpinned future release.

That SDK:

1. detaches the streamable connection context from `Connect`;
2. creates session cleanup `DELETE` with that detached context;
3. waits for `HTTPClient.Do` to return; and only then
4. cancels the connection context.

PR 97 deferred contextless `session.Close()` while `enumerateAll` waited for the
worker. `DisableStandaloneSSE=true` closed the earlier pre-session GET hang but
did not bound this distinct post-enumeration cleanup request.

A real stateful in-process MCP peer completed initialize, assigned a session,
observed `DELETE`, and withheld its response. Before the patch:

```text
go test ./modules/mcp -run '^TestMCPCollectorBoundsStreamableSessionDeleteByPerServerTimeout$' -count=1 -v
Collect outlived the public per-server timeout while session DELETE was stalled
FAIL (1.00s with a 100ms server timeout)
```

The test closes only its own temporary client connections after the failure so
the bug-presence run cannot leak a goroutine or hang the test process.

### Implementation

The collector now clones the concrete streamable/SSE HTTP client and wraps its
round tripper with the already established `deadlineRoundTripper`, using the
absolute deadline from the per-server context.

This design was selected because:

- it also covers the default-client path with no headers and no `--insecure`;
- one absolute deadline preserves the advertised total server budget;
- a fresh relative timeout per request could extend work past that budget;
- no blanket client timeout is added to long-lived protocol traffic;
- configured headers, TLS behavior, redirect behavior, initialize observation,
  streamable POSTs, and legacy SSE fallback remain composed in the same client;
  and
- no new CLI argument or operator decision is introduced.

The reviewer's reference to the legacy SSE fallback as another session-DELETE
path is not technically applicable: the pinned legacy SSE client closes its
response body and sends no cleanup DELETE. Applying the same absolute HTTP
deadline to fallback requests is conservative consistency, but the demonstrated
root defect is streamable cleanup.

### Negative controls

The final production-path regression requires all of the following:

- initialize and enumeration complete successfully;
- a stateful session `DELETE` is actually attempted;
- the peer holds `DELETE` until its request context is canceled;
- collection returns within the public timeout plus bounded CI slack;
- the peer observes cancellation; and
- successful enumeration remains a complete collection despite best-effort
  cleanup reaching the deadline.

Post-fix results:

```text
go test ./modules/mcp -run '^TestMCPCollectorBoundsStreamableSessionDeleteByPerServerTimeout$' -count=10 -v
PASS (each run approximately 100-110ms)

go test -race ./modules/mcp -count=1
PASS
```

## Stack validation

The rewritten review stack is:

```text
6171b8eccf9c9d82935c931c43c887d1d5e9cb34  Stack 2 / PR 97
a1890607d390d8d662594d88f945ef17a011a0ab  Stack 3 / PR 98
5f34f4c5fb48b8cdfeeca3878c57a6d9f7a4a5ad  Stack 4 / PR 99
32b0482d2607acfb60dbae892d4e76e0fd672fb0  Stack 5 / PR 100
3fac021067c4f3c76c4ba80164271de057f202eb  Stack 6 / PR 101
```

Validation completed after the rebase:

- full `go test ./... -race` on Stack 2: pass;
- full `go test ./... -race` on Stack 3: pass;
- full `go test ./... -race` on final Stack 6: pass;
- `go build ./...`: pass;
- `go vet ./...`: pass;
- `scripts/deps-check.sh`: pass;
- `scripts/size-check.sh`: 11,051,192 bytes against 12,012,132-byte limit;
- exact `gofmt -l .`: no output;
- `git diff --check`: pass; and
- `make prerelease`: all 13 gates pass, including current `govulncheck`,
  license policy, lint, fresh short race tests, UI production build, and
  linux/amd64 plus darwin/arm64 cross-compiles.

The license scanner repeated its established informational inability to inspect
some assembly files. Vite repeated its established IIFE-name and large-chunk
advisories. Neither is caused by or functionally related to these changes.

## Remote review state

After local acceptance, the five draft product branches were updated with
explicit force-with-lease expectations against their previously observed remote
SHAs. The validation branch was fast-forwarded. No unexpected remote movement
was overwritten.

GitHub then reported the complete stack as linear and mergeable:

- PR 97: `4d61d0f -> 6171b8e`;
- PR 98: `6171b8e -> a189060`;
- PR 99: `a189060 -> 5f34f4c`;
- PR 100: `5f34f4c -> 32b0482`; and
- PR 101: `32b0482 -> 3fac021`.

PR 97's description no longer claims Audit issue 25 and now documents the
session-DELETE reproduction and negative control. PR 98 now owns Audit issue 25
and describes the single-group product invariant, collector correction, and
atomic lifecycle validation. PRs 99-101 were updated only for their rebased
commit/scope metadata; the moved A2A code disappeared from PR 99's delta.

The post-push Docs builds succeeded for all five PR heads. GitGuardian reported
success for all five. PR 101's Version Check also succeeded. Superseded duplicate
workflow runs were canceled by workflow concurrency; the corresponding latest
head runs succeeded and no failing required check was observed.

## Real-infrastructure qualification

The earlier clean 24/24 infrastructure run is not represented as a new run.
It remains valid for the unchanged assembled A2A implementation. The new MCP
cleanup boundary was instead exercised directly through the production
collector path against a real stateful HTTP MCP handler that negotiated a
session and stalled the exact SDK cleanup request. Re-running all 24 external
services would not add stronger evidence for the isolated DELETE cancellation
condition and was intentionally avoided.

No release tag, version promotion, database mutation, external credential use,
or production deployment was performed during this follow-up.

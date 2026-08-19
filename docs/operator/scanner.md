# Scanner guide

`agenthound scan` is the complete collector workflow. There is no separate discovery or service-collection command.

## Target behavior

Local collection always runs. The optional positional argument adds one host, CIDR, or `@targets-file`.

```bash
agenthound scan
agenthound scan ai-gateway.internal
agenthound scan 10.20.0.0/24
agenthound scan @targets.txt
```

A targetless scan seeds:

- loopback;
- active local unicast interfaces;
- endpoints found in supported local MCP client configuration;
- standard ports for the supported AI services.

Configured HTTP MCP hostnames also seed network and protocol discovery. AgentHound has no supported local A2A endpoint configuration source; A2A endpoints enter through the positional scope or protocol discovery rather than through an invented config format.

Public targets are accepted without an interactive gate. Multicast is rejected and expansion is capped at one million hosts to bound compute and memory.

## Execution order

1. Construct the immutable exclusion policy.
2. Create and checkpoint the artifact.
3. Parse local configuration, instruction files, and credentials without contacting endpoints.
4. Admit the initial target set.
5. Enumerate admitted configured MCP endpoints with configured authentication and discovered A2A endpoints through their protocol surface.
6. Scan, discover protocol shapes, and fingerprint open endpoints.
7. Run applicable anonymous service collection.
8. Repeatedly plan and execute authenticated collection and bounded proof candidates.
9. Retry only unresolved recovery records and finalize.

Every new target passes target admission. Every actual socket also passes the same policy after DNS resolution, which prevents later redirects, derived URLs, and module code from bypassing an earlier filter.

Positive protocol observations are retained in the graph before service planning. MCP and A2A observations at the same address remain distinct targets rather than being collapsed by URL alone.

## Exclusions

```bash
agenthound scan 10.20.0.0/16 \
  --exclude admin.internal \
  --exclude 10.20.4.12 \
  --exclude 10.20.8.0/24
```

Hostname comparison is case-insensitive and ignores a trailing DNS dot. IP literals and every DNS result are checked against exact-IP and CIDR exclusions. Mixed DNS results use only allowed addresses; if all results are excluded, no dial occurs. Redirect destinations, ContextForge management/cleanup URLs, and remote JWKS URLs are checked again.

Excluded configuration is still retained as graph evidence with a skipped network outcome. `--exclude` does not sandbox a configured stdio MCP child process.

The normalized exclusions are saved in `meta.extra.scan_execution.exclusions` and replayed by `agenthound revert`, so cleanup uses the same network boundary as the original scan.

## Planner behavior

The planner rebuilds deterministic indexes after each result. It orders candidates as follows:

1. exact target-associated authenticated collection;
2. anonymous collection;
3. compatible cross-target credential reuse;
4. differential MCP resource-access verification;
5. reversible ContextForge round trip;
6. deep/high-cost collection.

Candidate keys include module, canonical target, credential hash or anonymous identity, resource/tool, and deep mode. A failed key is not retried during the scan. New credentials and targets can produce new keys.

Only concrete supported material is executable: LiteLLM master/bearer/API keys, Open WebUI bearer/API keys, Jupyter tokens, and bearer material for A2A and MCP. Hashes, masks, unresolved environment/vault references, custom strings, and basic-auth guesses are not presented.

Credential candidates retain their parsed authentication scheme. Sharing a value hash does not convert Basic or custom material into Bearer material, and value-hash deduplication deterministically prefers the credential already associated with the target before lexical ID order.

Structured partial collector results remain in the graph, but the candidate is recorded as partial/failed rather than successful. Proof and compute actions require their exact positive oracle; receiving a non-empty graph alone is not success.

## Active mutation

ContextForge mutation is exclusive. Existing work is drained before it begins. The action records recovery data and checkpoints it before the write, applies a scan-specific marker, checkpoints the applied state, runs the oracle, restores immediately under a separate 90-second cleanup context, confirms the original, and checkpoints restoration.

Nothing else collects, acts, or replans while the marker is live. Unresolved cleanup stops all forward work even if a final retry later succeeds.

## Checkpoint behavior

The artifact is written to a same-directory temporary file, synchronized, permissioned `0600`, closed, and atomically installed. POSIX then synchronizes the parent directory; Windows uses `MoveFileExW` with replace and write-through flags.

Before replacement, failure preserves the old destination or leaves the first destination absent. After replacement, a durability failure leaves the new complete JSON installed and stops forward work. AgentHound never rolls back a committed replacement and creates no backup or sidecar.

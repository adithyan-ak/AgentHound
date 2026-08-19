# Writing modules

The public workflow is fixed: every module contributes to `agenthound scan`. Do not add a module-specific CLI verb or flags.

## Module categories

- `Scanner`: expands bounded target scope.
- `Fingerprinter`: identifies a concrete endpoint and returns graph evidence.
- Config/MCP/A2A collectors: parse local configuration or enumerate protocol state.
- `ServiceCollector`: performs deeper service-specific collection after fingerprinting.
- `PlannerAction`: generates and executes autonomous candidates using the accumulated local view.

The CLI keeps orchestration concrete. Do not introduce a generic workflow engine, DAG schema, policy language, LLM planner, or database dependency.

## Service collectors

Implement `sdk/action.ServiceCollector` and `sdk/module.Module`, then register the collector from its package:

```go
type Collector struct{}

func (*Collector) ID() string            { return "example.collect" }
func (*Collector) Action() action.Action { return action.Collect }
func (*Collector) Target() string        { return "example" }
func (*Collector) IsDestructive() bool   { return false }

func (*Collector) Collect(
    ctx context.Context,
    target action.Target,
    opts action.CollectOptions,
) (*action.CollectResult, error) {
    // bounded, target-specific collection
}
```

Normal and deep behavior comes from fixed planner presets. A collector must not read removed module-specific CLI flags.

## Planner actions

Planner actions live in the collector orchestration layer when they compose existing modules. They implement:

```go
type PlannerAction interface {
    ID() string
    Candidates(View) []Candidate
    Execute(context.Context, Candidate, Journal) (Result, error)
}
```

Candidate generation must be deterministic and side-effect free. A key binds module ID, canonical target, credential value hash or anonymous identity, resource/tool ID, and deep mode. Raw execution inputs remain memory-only.

Only add an autonomous action when it has:

- self-contained prerequisites;
- a specific target and compatible credential contract;
- a meaningful observable oracle;
- bounded time and output;
- no operator-generated payload requirement;
- immediate, independently confirmed cleanup for mutation.

Instruction poisoning and config implantation were removed because the collector cannot autonomously choose a meaningful attacker payload or endpoint.

## Contact policy

Every AgentHound-owned connection must carry the scan context and use `sdk/contact` at both request and final-dial boundaries. Never create `http.DefaultClient`, an unguarded `http.Transport`, or a bare `net.Dialer` in module code.

Derived URLs, redirects, cleanup clients, and JWKS retrieval are in scope. Tests must prove an excluded configured endpoint and an excluded redirect destination receive zero requests.

## Graph and credentials

Return ingest V1 graph facts with explicit observation domains. Credential nodes store concrete raw material in `properties.value` and its stable identity in `properties.value_hash`. Never place a mask, hash, or unresolved reference in `value`.

Service result ownership is attached to the scan observation that triggered it; planner execution does not publish a second artifact envelope.

Every emitted coverage outcome must have a matching declaration owned by the same collector prefix, and every declaration must have an outcome. Preserve a useful graph returned alongside structured partial errors, but return the partial error to the planner so the action is not recorded as successful.

Executable credential nodes must preserve the parsed `auth_method`. Candidate adapters must explicitly accept that scheme; never infer Bearer compatibility from a field name or from another credential with the same value hash.

## Mutation journal

Mutation recovery must go through the passed `Journal`:

1. `Prepare` exact original state and credential references;
2. checkpoint success is required before the first write;
3. `MarkApplied` immediately after the write;
4. run the oracle;
5. restore immediately under a detached bounded context;
6. confirm original state independently;
7. `MarkRestored`.

Do not create receipt files, state directories, engagement identifiers, confirmation sentinels, or separate recovery artifacts.

## Verification

Run focused package tests, then:

```bash
go test ./... -race
go vet ./...
make deps-check
make size-check
```

The final collector must also cross-compile without CGO for Linux amd64, Darwin arm64, and Windows amd64.

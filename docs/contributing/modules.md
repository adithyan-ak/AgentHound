# Writing modules

Modules contribute capabilities to `agenthound scan`. The collector owns orchestration and chooses applicable modules from accumulated evidence.

## Module types

| Type | Responsibility |
|---|---|
| Scanner | Expand and probe bounded target scope. |
| Fingerprinter | Identify a concrete service endpoint. |
| Config/MCP/A2A collector | Parse local configuration or enumerate protocol state. |
| ServiceCollector | Collect service-specific inventory and content. |
| PlannerAction | Generate and execute autonomous candidates over the current local view. |

The orchestration remains concrete Go code. Module additions must not introduce a workflow language, database, policy engine, or model-driven planner.

## Registration

1. Create `modules/<name>/`.
2. Implement `sdk/module.Module` and the applicable interface from `sdk/action`.
3. Register the module in `init()` with `module.Register`.
4. Blank-import the package from `collector/cmd/agenthound/main.go`.
5. Add its packages to `scripts/collector-allowlist.txt`.
6. Add focused fixtures and tests.

Service collectors implement `sdk/action.ServiceCollector`:

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
    // bounded target-specific collection
}
```

Normal and deep behavior comes from planner presets. Modules do not define their own operator flags.

## Network boundary

Every AgentHound-owned connection must use `sdk/contact` from request construction through the final dial. This includes redirects, derived URLs, management and cleanup clients, and JWKS retrieval.

Do not use `http.DefaultClient`, an unguarded `http.Transport`, or a bare `net.Dialer`. Tests must demonstrate zero requests to an excluded configured endpoint, resolved IP, and redirect destination.

## Graph results

Return ingest V1 graph facts with deterministic IDs and explicit observation domains. Every collection outcome needs a matching coverage declaration owned by the same collector prefix.

Treat V1 as a backward-compatible wire contract: new fields must be optional,
and the current server must continue accepting the frozen historical V1
fixtures. Any required or otherwise breaking wire change starts a new contract
version instead of tightening V1 in place.

Preserve useful graph data returned with a structured partial error, but propagate the error so the planner does not record a false success.

Credential nodes follow these rules:

- Concrete material goes in `properties.value`.
- `properties.value_hash` is SHA-256 of the concrete material.
- Masked, hashed, and unresolved references retain their honest material status and omit `value`.
- Executable material retains its parsed `auth_method`.
- Candidate adapters accept explicit authentication schemes rather than inferring compatibility from names or hashes.

## Planner actions

Planner actions expose deterministic, side-effect-free candidate generation and bounded execution:

```go
type PlannerAction interface {
    ID() string
    Candidates(View) []Candidate
    Execute(context.Context, Candidate, Journal) (Result, error)
}
```

An action needs self-contained prerequisites, a specific target and credential contract, a meaningful oracle, bounded time and output, and an autonomous input strategy. Mutating actions also need exact recovery data and independent confirmation of restoration.

Mutation recovery uses the supplied Journal:

1. Prepare exact original state and credential references.
2. Require a successful checkpoint before the first write.
3. Mark and checkpoint the applied state immediately after the write.
4. Run the oracle.
5. Restore under a detached bounded context.
6. Confirm the original independently.
7. Mark and checkpoint restoration.

The action holds the exclusive mutation lease through cleanup. It must not create separate recovery files.

## Verification

```bash
go test ./modules/<name> ./sdk/... -race
go vet ./...
make deps-check
make size-check
```

The collector must continue to cross-compile without CGO for supported Linux, macOS, and Windows targets.

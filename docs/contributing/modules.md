# Writing a Module

Modules are self-registering units that perform a specific action against a target service. They live in `modules/<name>/` and register at `init()` time via `sdk/module.Register()`.

## Action Interfaces

Choose the interface that matches your module's purpose:

| Interface | Action | Contract | Mutating? |
|-----------|--------|----------|-----------|
| `Fingerprinter` | `fingerprint` | Probe a target, identify the service kind/version/auth | No |
| `Looter` | `loot` | Extract secrets/state via GET/HEAD only | No |
| `Extractor` | `extract` | Pull specific resources by reference (compute-heavy) | No (billing-heavy) |
| `Poisoner` | `poison` | Inject content into upstream artifacts | **Yes** -- requires Reverter |
| `Implanter` | `implant` | Plant persistent backdoors in target config | **Yes** -- requires Reverter |

All interfaces are defined in `sdk/action/`. Every module also implements `sdk/module.Module`:

```go
type Module interface {
    ID() string            // dotted lowercase: "ollama.fingerprint"
    Action() action.Action // action.Fingerprint, action.Loot, etc.
    Target() string        // service kind: "ollama", "litellm", "mcp"
    Description() string   // one-line summary
    Version() string       // semver
    IsDestructive() bool   // true for Poisoner/Implanter
}
```

## Step-by-Step: Creating a Fingerprinter

We'll use `modules/ollamafp/` as the worked example.

### 1. Create the directory

```
modules/yourservice/
    register.go
    fingerprinter.go
    fingerprinter_test.go
```

### 2. Implement the action interface

`fingerprinter.go`:

```go
package yourservicefp

import (
    "context"
    "github.com/adithyan-ak/agenthound/sdk/action"
    "github.com/adithyan-ak/agenthound/sdk/ingest"
    "github.com/adithyan-ak/agenthound/sdk/rules"
)

type Fingerprinter struct {
    rule *rules.FingerprintRule
}

func New() (*Fingerprinter, error) {
    all, err := rules.LoadFingerprints()
    if err != nil {
        return nil, err
    }
    for _, r := range all {
        if r.ServiceKind == "yourservice" {
            rule := r
            return &Fingerprinter{rule: &rule}, nil
        }
    }
    return nil, errors.New("yourservice fingerprint rule not found")
}

func (f *Fingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
    // Build base URL from t.Address
    // Run the probe via rules.RunFingerprint(ctx, client, baseURL, *f.rule)
    // On match: build ingest.Node with multi-label kinds, return FingerprintResult
    // On no-match: return &action.FingerprintResult{Matched: false}, nil
}

var _ action.Fingerprinter = (*Fingerprinter)(nil)
```

Key points from the `ollamafp` implementation:
- Load the fingerprint rule from `sdk/rules/builtin/fingerprints/` by `service_kind`
- Use `rules.RunFingerprint()` to dispatch the HTTP probe and matchers
- Compute deterministic node ID via `ingest.ComputeNodeID("YourKind", endpoint)`
- Return `IngestData` with multi-label node (e.g., `["YourKind", "AIService"]`)

### 3. Write register.go

```go
package yourservicefp

import (
    "log/slog"
    "github.com/adithyan-ak/agenthound/sdk/action"
    "github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
    f, err := New()
    if err != nil {
        slog.Warn("yourservice fingerprinter init failed", "error", err)
        module.Register(&disabledFingerprinter{})
        return
    }
    module.Register(f)
}

func (*Fingerprinter) ID() string            { return "yourservice.fingerprint" }
func (*Fingerprinter) Action() action.Action { return action.Fingerprint }
func (*Fingerprinter) Target() string        { return "yourservice" }
func (*Fingerprinter) Description() string   { return "Identify YourService by ..." }
func (*Fingerprinter) Version() string       { return "0.1.0" }
func (*Fingerprinter) IsDestructive() bool   { return false }

// disabledFingerprinter -- fallback when rule fails to load.
type disabledFingerprinter struct{}
// ... implement Module interface, return Matched=false from Fingerprint
```

Pattern: always register something (even a disabled stub) so registry lookups succeed and the scanner can skip gracefully.

### 4. Blank-import in main.go

Add to `collector/cmd/agenthound/main.go`:

```go
_ "github.com/adithyan-ak/agenthound/modules/yourservicefp"
```

### 5. Add to the collector allowlist

Update `scripts/collector-allowlist.txt` with any new transitive dependencies your module introduces. CI will reject unlisted deps.

### 6. Write tests

Use `httptest.Server` to mock the target service. Test both the matching and non-matching cases:

```go
func TestFingerprint_Match(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"version": "1.0.0"})
    }))
    defer srv.Close()

    fp, err := New()
    require.NoError(t, err)

    target := action.Target{Address: srv.Listener.Addr().String(), Meta: map[string]string{"scheme": "http"}}
    result, err := fp.Fingerprint(context.Background(), target)
    require.NoError(t, err)
    assert.True(t, result.Matched)
}
```

## Optional Sidecar Interfaces

### FlagsModule -- Per-Module CLI Flags

For modules that need CLI flags beyond the standard set:

```go
import "github.com/spf13/pflag"

func (f *YourLooter) RegisterFlags(fs *pflag.FlagSet) {
    fs.BoolVar(&f.includeWeights, "include-weights", false, "Download model weight files")
    fs.StringVar(&f.weightsDir, "weights-dir", "", "Directory for weight storage")
}
```

The CLI dispatcher calls `module.RegisterFlagsFor(cmd, mod)` which type-asserts for `FlagsModule`. Flag values are available at dispatch time via `LootOptions.Extras` or `PoisonPayload.Extras`.

### StatefulModule -- Receipt Persistence

For destructive modules (Poisoner, Implanter) that need revert capability:

```go
type YourPoisoner struct {
    state *module.FileStatefulModule
}

func New() *YourPoisoner {
    return &YourPoisoner{
        state: module.NewFileStatefulModule("yourservice.poison"),
    }
}

func (p *YourPoisoner) StateDir() string { return p.state.StateDir() }
func (p *YourPoisoner) WriteReceipt(engagementID string, r action.Receipt) (string, error) {
    return p.state.WriteReceipt(engagementID, r)
}
func (p *YourPoisoner) ReadReceipts(engagementID string) ([]action.Receipt, error) {
    return p.state.ReadReceipts(engagementID)
}
```

Receipts are stored at `~/.agenthound/state/<module-id>/<engagement-id>.json` with mode 0o600. The CLI persists the receipt AFTER the poison succeeds but BEFORE reporting success -- crash between mutation and receipt write is the one unrecoverable failure mode.

## Registry Lookup

Modules are resolved by the CLI and scanner via:

```go
module.Get("ollama.fingerprint")                    // by ID
module.ListByAction(action.Fingerprint)             // all fingerprinters
module.GetByTarget("ollama", action.Fingerprint)    // by (target, action) pair
```

## Checklist

- [ ] Implements one action interface from `sdk/action/`
- [ ] Implements `sdk/module.Module`
- [ ] Has `register.go` with `init()` calling `module.Register()`
- [ ] Blank-imported in `collector/cmd/agenthound/main.go`
- [ ] Added to `scripts/collector-allowlist.txt` (if new deps)
- [ ] Tests cover match, no-match, and error cases
- [ ] `make build-collector && make deps-check` passes
- [ ] `IsDestructive()` returns true for Poisoner/Implanter modules
- [ ] Fingerprint rule YAML added to `sdk/rules/builtin/fingerprints/` (for fingerprinters)

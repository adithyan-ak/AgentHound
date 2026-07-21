# AgentHound modules

Most subdirectories implement an `sdk/action` interface and self-register with
`sdk/module` via `init()`. The collector binary (`collector/cmd/agenthound`)
blank-imports those packages so registration happens at startup:

    import (
        _ "github.com/adithyan-ak/agenthound/modules/mcp"
        _ "github.com/adithyan-ak/agenthound/modules/a2a"
        _ "github.com/adithyan-ak/agenthound/modules/config"
    )

The current exceptions are intentional:

- `config`, `mcp`, and `a2a` register compatibility metadata but their legacy
  collectors, not `sdk/action.Enumerator`, drive enumeration.
- `credreach` and `mcproundtrip` register with `sdk/campaign`.
- `protoscan` is a discovery engine, not an `sdk/module` registration.

## Adding a new action module

1. Create `modules/<name>/`.
2. Implement a CLI-dispatched `sdk/action` interface (Fingerprinter, Looter,
   Extractor, Poisoner, Implanter, ...). `Enumerator` is not currently
   dispatched as a third-party extension point.
3. Add `register.go`:

       func init() { module.Register(&<Name>{}) }

4. Add the blank-import line to `collector/cmd/agenthound/main.go`.
5. Add the module package and any new dependency packages to
   `scripts/collector-allowlist.txt`.

There is no runtime plugin loading or DLL mechanism; registration is compiled
into the collector.

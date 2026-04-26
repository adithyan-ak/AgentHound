# AgentHound modules

Each subdirectory implements one or more `sdk/action` interfaces and self-registers
with `sdk/module` via `init()`. The collector binary (`collector/cmd/agenthound`)
blank-imports each module package so registration happens at startup:

    import (
        _ "github.com/adithyan-ak/agenthound/modules/mcp"
        _ "github.com/adithyan-ak/agenthound/modules/a2a"
        _ "github.com/adithyan-ak/agenthound/modules/config"
    )

## Adding a new module

1. Create `modules/<name>/`.
2. Implement an `sdk/action` interface (Enumerator, Fingerprinter, Looter, ...).
3. Add `register.go`:

       func init() { module.Register(&<Name>{}) }

4. Add the blank-import line to `collector/cmd/agenthound/main.go`.

That's it — no plugin loading, no runtime DLLs. Compile-time registration only.

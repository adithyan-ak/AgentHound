package instructionpoison

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(New())
}

func (*Poisoner) ID() string            { return "instruction.poison" }
func (*Poisoner) Action() action.Action { return action.Poison }
func (*Poisoner) Target() string        { return "instruction.file" }
func (*Poisoner) Description() string {
	return "Append a sentinel-bracketed instruction block to CLAUDE.md / AGENTS.md / .cursorrules"
}
func (*Poisoner) Version() string     { return "0.4.0-dev" }
func (*Poisoner) IsDestructive() bool { return true }

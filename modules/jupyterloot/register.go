package jupyterloot

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Looter{})
}

func (*Looter) ID() string            { return "jupyter.loot" }
func (*Looter) Action() action.Action { return action.Loot }
func (*Looter) Target() string        { return "jupyter" }
func (*Looter) Description() string {
	return "Extract notebook inventory and active sessions from a Jupyter Server (anonymous, GET-only)"
}
func (*Looter) Version() string     { return "0.4.0-dev" }
func (*Looter) IsDestructive() bool { return false }

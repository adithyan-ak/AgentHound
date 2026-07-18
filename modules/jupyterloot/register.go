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
	return "Inventory Jupyter sessions and contents with control-first GETs and optional bearer retry"
}
func (*Looter) Version() string     { return "0.4.0-dev" }
func (*Looter) IsDestructive() bool { return false }

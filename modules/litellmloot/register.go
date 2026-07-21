package litellmloot

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Looter{})
}

func (*Looter) ID() string            { return "litellm.loot" }
func (*Looter) Action() action.Action { return action.Loot }
func (*Looter) Target() string        { return "litellm" }
func (*Looter) Description() string {
	return "Inventory an observed master key plus masked provider and hashed virtual-key references from a LiteLLM gateway (read-only; GET only)"
}
func (*Looter) Version() string     { return "0.2.0-dev" }
func (*Looter) IsDestructive() bool { return false }

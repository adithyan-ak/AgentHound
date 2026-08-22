package litellmcollect

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Collector{})
}

func (*Collector) ID() string            { return "litellm.collect" }
func (*Collector) Action() action.Action { return action.Collect }
func (*Collector) Target() string        { return "litellm" }
func (*Collector) Description() string {
	return "Inventory an observed master key plus masked provider and hashed virtual-key references from a LiteLLM gateway (read-only; GET only)"
}
func (*Collector) Version() string     { return "0.2.0-dev" }
func (*Collector) IsDestructive() bool { return false }

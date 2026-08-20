package jupytercollect

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Collector{})
}

func (*Collector) ID() string            { return "jupyter.collect" }
func (*Collector) Action() action.Action { return action.Collect }
func (*Collector) Target() string        { return "jupyter" }
func (*Collector) Description() string {
	return "Inventory Jupyter sessions and contents with control-first GETs and optional bearer retry"
}
func (*Collector) Version() string     { return "0.4.0-dev" }
func (*Collector) IsDestructive() bool { return false }

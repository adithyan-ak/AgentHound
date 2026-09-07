package qdrantcollect

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Collector{})
}

func (*Collector) ID() string            { return "qdrant.collect" }
func (*Collector) Action() action.Action { return action.Collect }
func (*Collector) Target() string        { return "qdrant" }
func (*Collector) Description() string {
	return "Collect Qdrant collections and point counts, with bounded point-reference sampling in deep mode"
}
func (*Collector) Version() string     { return "0.4.0-dev" }
func (*Collector) IsDestructive() bool { return false }

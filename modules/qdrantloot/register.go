package qdrantloot

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Looter{})
}

func (*Looter) ID() string            { return "qdrant.loot" }
func (*Looter) Action() action.Action { return action.Loot }
func (*Looter) Target() string        { return "qdrant" }
func (*Looter) Description() string {
	return "Inventory Qdrant collections and per-collection point counts (anonymous, GET-only)"
}
func (*Looter) Version() string     { return "0.4.0-dev" }
func (*Looter) IsDestructive() bool { return false }

package mlflowloot

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Looter{})
}

func (*Looter) ID() string            { return "mlflow.loot" }
func (*Looter) Action() action.Action { return action.Loot }
func (*Looter) Target() string        { return "mlflow" }
func (*Looter) Description() string {
	return "Extract experiment metadata and run inventory from an MLflow Tracking Server (anonymous, GET-only)"
}
func (*Looter) Version() string     { return "0.4.0-dev" }
func (*Looter) IsDestructive() bool { return false }

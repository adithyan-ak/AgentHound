package mlflowcollect

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Collector{})
}

func (*Collector) ID() string            { return "mlflow.collect" }
func (*Collector) Action() action.Action { return action.Collect }
func (*Collector) Target() string        { return "mlflow" }
func (*Collector) Description() string {
	return "Extract experiment metadata and run inventory from an MLflow Tracking Server (anonymous, GET-only)"
}
func (*Collector) Version() string     { return "0.4.0-dev" }
func (*Collector) IsDestructive() bool { return false }

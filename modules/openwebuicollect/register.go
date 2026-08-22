package openwebuicollect

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Collector{})
}

func (*Collector) ID() string            { return "openwebui.collect" }
func (*Collector) Action() action.Action { return action.Collect }
func (*Collector) Target() string        { return "openwebui" }
func (*Collector) Description() string {
	return "Collect Open WebUI posture and authenticated upstream provider keys"
}
func (*Collector) Version() string     { return "0.4.0-dev" }
func (*Collector) IsDestructive() bool { return false }

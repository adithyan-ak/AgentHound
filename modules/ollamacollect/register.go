package ollamacollect

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Collector{})
}

func (*Collector) ID() string            { return "ollama.collect" }
func (*Collector) Action() action.Action { return action.Collect }
func (*Collector) Target() string        { return "ollama" }
func (*Collector) Description() string {
	return "Collect Ollama model inventory and modelfiles, with bounded embeddings in deep active mode"
}
func (*Collector) Version() string     { return "0.3.0-dev" }
func (*Collector) IsDestructive() bool { return false }

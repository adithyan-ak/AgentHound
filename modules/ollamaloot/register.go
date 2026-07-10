package ollamaloot

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Looter{})
}

func (*Looter) ID() string            { return "ollama.loot" }
func (*Looter) Action() action.Action { return action.Loot }
func (*Looter) Target() string        { return "ollama" }
func (*Looter) Description() string {
	return "Extract Ollama model inventory + modelfiles (anonymous; flag-gated embeddings)"
}
func (*Looter) Version() string     { return "0.3.0-dev" }
func (*Looter) IsDestructive() bool { return false }

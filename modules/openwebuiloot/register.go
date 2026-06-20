package openwebuiloot

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&Looter{})
}

func (*Looter) ID() string            { return "openwebui.loot" }
func (*Looter) Action() action.Action { return action.Loot }
func (*Looter) Target() string        { return "openwebui" }
func (*Looter) Description() string {
	return "Capture Open WebUI posture (anonymous /api/config) and authenticated upstream provider keys (--api-key, GET-only)"
}
func (*Looter) Version() string     { return "0.4.0-dev" }
func (*Looter) IsDestructive() bool { return false }

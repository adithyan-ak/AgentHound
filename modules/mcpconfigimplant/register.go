package mcpconfigimplant

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(New())
}

func (*Implanter) ID() string            { return "mcp.config.implant" }
func (*Implanter) Action() action.Action { return action.Implant }
func (*Implanter) Target() string        { return "mcp.config.malicious-server" }
func (*Implanter) Description() string {
	return "Add a malicious MCP server entry to a client config (.cursor/mcp.json etc.)"
}
func (*Implanter) Version() string     { return "0.4.0-dev" }
func (*Implanter) IsDestructive() bool { return true }

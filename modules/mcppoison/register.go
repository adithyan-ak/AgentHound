package mcppoison

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(New())
}

func (*Poisoner) ID() string            { return "mcp.poison" }
func (*Poisoner) Action() action.Action { return action.Poison }
func (*Poisoner) Target() string        { return "mcp.tool.description" }
func (*Poisoner) Description() string {
	return "Run a reversible ContextForge-managed MCP tool-description proof with immediate restoration"
}
func (*Poisoner) Version() string     { return "0.4.0-dev" }
func (*Poisoner) IsDestructive() bool { return true }

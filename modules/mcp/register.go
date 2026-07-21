package mcp

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&MCPEnumerator{})
}

// MCPEnumerator is the registration shim for the MCP module.
//
// It satisfies sdk/module.Module via the six identity methods below. It does
// not implement sdk/action.Enumerator; the MCPCollector implementation of
// sdk/collector.Collector drives runtime work directly from the CLI.
//
// Action() == action.Enumerate is registry metadata and does not imply that the
// registered value implements the action interface.
type MCPEnumerator struct{}

func (*MCPEnumerator) ID() string            { return "mcp.enumerate" }
func (*MCPEnumerator) Action() action.Action { return action.Enumerate }
func (*MCPEnumerator) Target() string        { return "mcp" }
func (*MCPEnumerator) Description() string {
	return "Enumerate Model Context Protocol servers, tools, resources, prompts, and signals"
}
func (*MCPEnumerator) Version() string     { return "0.1.0" }
func (*MCPEnumerator) IsDestructive() bool { return false }

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
// It satisfies sdk/module.Module via the six identity methods below. The
// sdk/action.Enumerator interface (with the Enumerate(ctx, Target, opts)
// method) is intentionally NOT implemented here yet — the legacy
// internal/collector.Collector implementation in collector.go still drives
// runtime work, and a later step will adapt this struct to delegate to it.
//
// Because sdk/action.Enumerator is a Go interface and we never type-assert
// to it from the registry, this struct can claim the "enumerator" role via
// Action() == action.Enumerate without yet exposing the action method.
type MCPEnumerator struct{}

func (*MCPEnumerator) ID() string            { return "mcp.enumerate" }
func (*MCPEnumerator) Action() action.Action { return action.Enumerate }
func (*MCPEnumerator) Target() string        { return "mcp" }
func (*MCPEnumerator) Description() string {
	return "Enumerate Model Context Protocol servers, tools, resources, prompts, and signals"
}
func (*MCPEnumerator) Version() string     { return "0.1.0" }
func (*MCPEnumerator) IsDestructive() bool { return false }

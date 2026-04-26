package config

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&ConfigEnumerator{})
}

// ConfigEnumerator is the registration shim for the Config module.
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
type ConfigEnumerator struct{}

func (*ConfigEnumerator) ID() string            { return "config.enumerate" }
func (*ConfigEnumerator) Action() action.Action { return action.Enumerate }
func (*ConfigEnumerator) Target() string        { return "config" }
func (*ConfigEnumerator) Description() string {
	return "Discover and parse local MCP/A2A client configs, instruction files, and credentials"
}
func (*ConfigEnumerator) Version() string     { return "0.1.0" }
func (*ConfigEnumerator) IsDestructive() bool { return false }

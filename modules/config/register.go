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
// It satisfies sdk/module.Module via the six identity methods below. It does
// not implement sdk/action.Enumerator; the ConfigCollector implementation of
// sdk/collector.Collector drives runtime work directly from the CLI.
//
// Action() == action.Enumerate is registry metadata and does not imply that the
// registered value implements the action interface.
type ConfigEnumerator struct{}

func (*ConfigEnumerator) ID() string            { return "config.enumerate" }
func (*ConfigEnumerator) Action() action.Action { return action.Enumerate }
func (*ConfigEnumerator) Target() string        { return "config" }
func (*ConfigEnumerator) Description() string {
	return "Discover and parse local MCP/A2A client configs, instruction files, and credentials"
}
func (*ConfigEnumerator) Version() string     { return "0.1.0" }
func (*ConfigEnumerator) IsDestructive() bool { return false }

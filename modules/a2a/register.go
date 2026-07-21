package a2a

import (
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func init() {
	module.Register(&A2AEnumerator{})
}

// A2AEnumerator is the registration shim for the A2A module.
//
// It satisfies sdk/module.Module via the six identity methods below. It does
// not implement sdk/action.Enumerator; the A2ACollector implementation of
// sdk/collector.Collector drives runtime work directly from the CLI.
//
// Action() == action.Enumerate is registry metadata and does not imply that the
// registered value implements the action interface.
type A2AEnumerator struct{}

func (*A2AEnumerator) ID() string            { return "a2a.enumerate" }
func (*A2AEnumerator) Action() action.Action { return action.Enumerate }
func (*A2AEnumerator) Target() string        { return "a2a" }
func (*A2AEnumerator) Description() string {
	return "Fetch and parse A2A agent cards over HTTP, including JWS signature verification"
}
func (*A2AEnumerator) Version() string     { return "0.1.0" }
func (*A2AEnumerator) IsDestructive() bool { return false }

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
// It satisfies sdk/module.Module via the six identity methods below. The
// sdk/action.Enumerator interface (with the Enumerate(ctx, Target, opts)
// method) is intentionally NOT implemented here yet — the legacy
// internal/collector.Collector implementation in collector.go still drives
// runtime work, and a later step will adapt this struct to delegate to it.
//
// Because sdk/action.Enumerator is a Go interface and we never type-assert
// to it from the registry, this struct can claim the "enumerator" role via
// Action() == action.Enumerate without yet exposing the action method.
type A2AEnumerator struct{}

func (*A2AEnumerator) ID() string            { return "a2a.enumerate" }
func (*A2AEnumerator) Action() action.Action { return action.Enumerate }
func (*A2AEnumerator) Target() string        { return "a2a" }
func (*A2AEnumerator) Description() string {
	return "Fetch and parse A2A agent cards over HTTP, including JWS signature verification"
}
func (*A2AEnumerator) Version() string     { return "0.1.0" }
func (*A2AEnumerator) IsDestructive() bool { return false }

// Package module declares the AgentHound module super-interface and a
// process-global registry. Modules self-register at init() time; the collector
// CLI resolves compiled registrations by ID, Action, or Target kind.
//
// Stability: v1 follows semantic versioning. Breaking changes to exported
// module contracts require a major-version bump and at least one deprecation
// cycle.
package module

import "github.com/adithyan-ak/agenthound/sdk/action"

// Module is the super-interface every registered module satisfies in
// addition to one or more action interfaces.
type Module interface {
	ID() string            // dotted lowercase, e.g. "mcp.enumerate"
	Action() action.Action // which action this module performs
	Target() string        // service kind targeted, e.g. "mcp", "a2a", "config"
	Description() string   // one-line human-readable summary
	Version() string       // semver of the module
	IsDestructive() bool   // reports whether the action may mutate target state
}

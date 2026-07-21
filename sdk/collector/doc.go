// Package collector defines the collection contract used by the built-in
// Config, MCP, and A2A collectors. The CLI constructs those concrete collectors
// directly; it does not dispatch sdk/action.Enumerator through the module
// registry.
//
// Stability: v1 follows semantic versioning. Breaking changes to exported
// collector contracts require a major-version bump and at least one
// deprecation cycle.
package collector

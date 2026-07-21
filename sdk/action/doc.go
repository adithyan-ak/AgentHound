// Package action declares the AgentHound action interface contracts.
//
// Each Action represents a distinct phase of an AI infrastructure red-team
// engagement. Modules implement one or more of these interfaces to plug into
// the framework via the sdk/module registry.
//
//	Scan         — CIDR/range expansion → []Target
//	Fingerprint  — single Target → service identification
//	Enumerate    — reserved single-Target graph-patch contract; not dispatched by the current CLI
//	Loot         — extract latent secrets / state from a service
//	Extract      — analyze a specific operator-supplied resource by reference
//	Poison       — inject content into an upstream artifact (composes Reverter)
//	Implant      — install a persistent payload (composes Reverter)
//
// Stability: v1 follows semantic versioning. Breaking changes to exported
// action contracts require a major-version bump and at least one deprecation
// cycle. Availability is separate from API stability: the current CLI does not
// dispatch Enumerator, and Config/MCP/A2A enumeration is driven by legacy
// collector implementations.
//
// An action module satisfies BOTH this package's action interface AND the
// sdk/module.Module interface. The action interfaces here deliberately do
// NOT embed module.Module to avoid an import cycle (sdk/module depends on
// sdk/action for the Action enum). Implementations declare both contracts
// explicitly.
package action

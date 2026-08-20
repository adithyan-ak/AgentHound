// Package action declares the AgentHound action interface contracts.
//
// Modules implement one or more interfaces and register them for autonomous
// dispatch inside the single scan workflow.
//
//	Scan         — CIDR/range expansion → []Target
//	Fingerprint  — single Target → service identification
//	Enumerate    — configuration or protocol collection metadata
//	Collect      — deep service inventory and credential acquisition
//	Poison       — internal reversible ContextForge adapter used by the planner
//
// Stability: v1 follows semantic versioning. Breaking changes to exported
// action contracts require a major-version bump and at least one deprecation
// cycle.
//
// An action module satisfies BOTH this package's action interface AND the
// sdk/module.Module interface. The action interfaces here deliberately do
// NOT embed module.Module to avoid an import cycle (sdk/module depends on
// sdk/action for the Action enum). Implementations declare both contracts
// explicitly.
package action

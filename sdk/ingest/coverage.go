package ingest

// Contract versions. These are independent of the ingest wire Version
// (IngestMeta.Version, pinned at 1 by the validator):
//
//   - CurrentSchemaVersion tracks the shape of the canonical artifact/graph
//     contract. Bump it whenever a contract change requires a coordinated
//     database reset / re-ingest rather than a backward-compatible read.
//   - CurrentIdentityVersion tracks the node-identity derivation scheme (the
//     deterministic content hash inputs). Bump it whenever two collectors
//     that must merge on a shared ID would otherwise disagree — e.g. the MCP
//     server ID argv-order change. A mismatch means the graph must be rebuilt.
const (
	CurrentSchemaVersion = 1
	// CurrentIdentityVersion is 2 as of the MCP server-ID argv-order change:
	// ComputeMCPServerID no longer sorts stdio args, so IDs produced under
	// version 1 (sorted) do not match version 2 (order-preserving). A graph
	// that mixes the two would fail to merge config + MCP observations of the
	// same server, so a version bump forces a coordinated rebuild/re-ingest.
	CurrentIdentityVersion = 2
)

// CollectionStatus is the terminal state of a collection scope (a whole
// artifact, a single target, or a single method). It makes "absence is not
// evidence" explicit: an empty artifact is only clean when Status is
// StatusComplete. Anything else means the reader MUST treat the posture as
// incomplete and MUST NOT coalesce it into an all-clear/zero verdict.
type CollectionStatus string

const (
	// StatusComplete means every requested unit of work in this scope ran to
	// completion. Absence of a fact within a complete scope is real evidence.
	StatusComplete CollectionStatus = "complete"
	// StatusPartial means some requested work completed and some did not.
	// Present facts are trustworthy; absent facts are inconclusive.
	StatusPartial CollectionStatus = "partial"
	// StatusFailed means the scope produced no trustworthy observations.
	StatusFailed CollectionStatus = "failed"
	// StatusUnknown means the scope was never assessed (e.g. a domain that was
	// not requested). Distinct from StatusFailed, which was attempted.
	StatusUnknown CollectionStatus = "unknown"
)

// AllCollectionStatuses is the canonical ordered set of collection statuses,
// consumed by the TypeScript generator and by validity checks.
var AllCollectionStatuses = []CollectionStatus{
	StatusComplete, StatusPartial, StatusFailed, StatusUnknown,
}

// Valid reports whether s is one of the four defined statuses.
func (s CollectionStatus) Valid() bool {
	switch s {
	case StatusComplete, StatusPartial, StatusFailed, StatusUnknown:
		return true
	default:
		return false
	}
}

// IsClean reports whether an empty observation set within this scope can be
// treated as a genuine all-clear. Only a complete scope qualifies.
func (s CollectionStatus) IsClean() bool { return s == StatusComplete }

// CollectionCoverage records what a scan actually attempted and achieved, so
// downstream readers can distinguish "nothing found" from "nothing looked at".
// It travels on IngestMeta and is persisted per-scan.
type CollectionCoverage struct {
	// Status is the roll-up state for the whole artifact. It MUST be
	// StatusComplete only when every constituent target and method completed.
	Status CollectionStatus `json:"status"`
	// ConstituentCollectors names the collectors merged into this artifact
	// (e.g. a scan bundle merging "config", "mcp", "a2a"). Single-collector
	// artifacts carry exactly one entry.
	ConstituentCollectors []string `json:"constituent_collectors,omitempty"`
	// Targets is the per-target outcome for target-oriented collectors
	// (A2A agents, network hosts). Order-preserving.
	Targets []TargetOutcome `json:"targets,omitempty"`
	// Methods is the per-method outcome for method-oriented collectors
	// (MCP tools/list, resources/list, prompts/list). Order-preserving.
	Methods []MethodOutcome `json:"methods,omitempty"`
	// Rules is the manifest of detection/fingerprint rules that were active
	// during collection, so a finding's provenance can be reconstructed.
	Rules []RuleManifestEntry `json:"rules,omitempty"`
	// Truncated is true when output was capped (page/row/time limits).
	Truncated bool `json:"truncated,omitempty"`
	// TruncationReason explains what limit was hit when Truncated is true.
	TruncationReason string `json:"truncation_reason,omitempty"`
}

// TargetOutcome is the collection result for a single requested target.
type TargetOutcome struct {
	Target string           `json:"target"`
	Status CollectionStatus `json:"status"`
	Error  string           `json:"error,omitempty"`
}

// MethodOutcome is the collection result for a single method invocation
// against a target (e.g. MCP "tools/list" on a given server).
type MethodOutcome struct {
	Target string           `json:"target,omitempty"`
	Method string           `json:"method"`
	Status CollectionStatus `json:"status"`
	Error  string           `json:"error,omitempty"`
}

// RuleManifestEntry pins the identity of a rule that participated in
// collection or detection, so findings carry reconstructable provenance.
type RuleManifestEntry struct {
	RuleID  string `json:"rule_id"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

// RollupStatus computes an artifact-level status from a set of scope statuses
// using the "weakest link, but distinguish never-assessed" policy:
//
//   - any StatusFailed        → StatusPartial if others succeeded, else StatusFailed
//   - any StatusPartial       → StatusPartial
//   - mix of complete+unknown → StatusPartial (something was skipped)
//   - all StatusComplete      → StatusComplete
//   - all StatusUnknown / none → StatusUnknown
//
// The rule that "an empty artifact is clean only when every requested
// target/method completed" is enforced here: a lone skipped/failed unit
// downgrades the roll-up away from complete.
func RollupStatus(statuses ...CollectionStatus) CollectionStatus {
	if len(statuses) == 0 {
		return StatusUnknown
	}
	var complete, partial, failed, unknown int
	for _, s := range statuses {
		switch s {
		case StatusComplete:
			complete++
		case StatusPartial:
			partial++
		case StatusFailed:
			failed++
		default:
			unknown++
		}
	}
	switch {
	case partial > 0:
		return StatusPartial
	case failed > 0:
		if complete > 0 || partial > 0 {
			return StatusPartial
		}
		return StatusFailed
	case complete > 0 && unknown > 0:
		return StatusPartial
	case complete > 0:
		return StatusComplete
	default:
		return StatusUnknown
	}
}

package campaign

// OracleTypeReversibleMutationRoundtrip identifies the STANDALONE
// target-mutation validation oracle: an operator-authorized mutation is applied,
// the exact injected state is re-read (the oracle), a conflict-aware revert is
// issued, and restoration of the original state is verified (the cleanup).
//
// It is deliberately NOT an attack oracle. It proves the reversible mutation
// machinery works against this target — it does NOT prove that any agent
// selected, invoked, or was affected by the mutation, and it makes NO claim that
// a predicted credential path is real.
const OracleTypeReversibleMutationRoundtrip = "reversible_mutation_roundtrip"

// RoundtripOracle classifies whether the operator-authorized mutation actually
// landed on the target, decided by re-reading the exact live state after the
// mutation and comparing it to the receipt. It is INDEPENDENT of the cleanup.
type RoundtripOracle string

const (
	// OracleMutationVerified: the post-mutation re-read equals the receipt's
	// InjectedContent — the mutation landed exactly as intended.
	OracleMutationVerified RoundtripOracle = "mutation_verified"
	// OracleMutationNotApplied: the post-mutation re-read equals the receipt's
	// OriginalContent — the write did not change the live state (e.g. the write
	// surface silently ignored it, or the injection equalled the original).
	OracleMutationNotApplied RoundtripOracle = "mutation_not_applied"
	// OracleMutationConflict: the post-mutation re-read matches neither the
	// original nor the injected content — a third party changed the target
	// between the write and the re-read.
	OracleMutationConflict RoundtripOracle = "mutation_conflict"
	// OracleIndeterminate: the post-mutation re-read failed, so whether the
	// mutation landed is unknowable.
	OracleIndeterminate RoundtripOracle = "indeterminate"
)

// RoundtripCleanup classifies whether the target was returned to its original
// state by the conflict-aware revert, verified by a post-revert re-read. It is
// INDEPENDENT of the oracle: a verified mutation can still fail to clean up
// (e.g. a third party edits the target between the oracle re-read and the
// revert), and that MUST be reported rather than masked.
type RoundtripCleanup string

const (
	// CleanupNotApplicable is used by read-only scenarios.
	CleanupNotApplicable RoundtripCleanup = "not_applicable"
	// CleanupRestored: the conflict-aware revert completed and a post-revert
	// re-read confirms the live state equals OriginalContent. This also covers a
	// no-op revert (the target already matched the original) — either way the
	// target is confirmed clean.
	CleanupRestored RoundtripCleanup = "restored"
	// CleanupConflict: the revert refused to overwrite a third-party change
	// (the conflict-aware guard). The receipt is retained for a later
	// `agenthound revert`.
	CleanupConflict RoundtripCleanup = "conflict"
	// CleanupIndeterminate: the revert could not re-read the live state, so it
	// wrote nothing (never a blind write). The receipt is retained.
	CleanupIndeterminate RoundtripCleanup = "indeterminate"
	// CleanupFailed: the revert attempted a restore but the write failed, or the
	// post-revert re-read did not observe the original. The receipt is retained.
	CleanupFailed RoundtripCleanup = "failed"
)

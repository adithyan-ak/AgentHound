package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestScopeFromScans_NoneWhenEmpty(t *testing.T) {
	s := scopeFromScans(nil)
	if s.Completeness.Complete {
		t.Error("empty scope must not be complete")
	}
	if s.Completeness.CoverageStatus != "none" {
		t.Errorf("coverage_status = %q, want none", s.Completeness.CoverageStatus)
	}
	if len(s.GenerationIDs) != 0 {
		t.Errorf("expected no generation ids, got %v", s.GenerationIDs)
	}
}

// okStages is the successful prerequisite stage set a promoted generation must
// carry for the scope to be complete (F4): write succeeded, post-processing and
// snapshot ok.
func okStages() map[string]ingest.StageState {
	return map[string]ingest.StageState{
		ingest.StageWrite:          ingest.StageSucceeded,
		ingest.StagePostProcessing: ingest.StageSucceeded,
		ingest.StageSnapshot:       ingest.StageSucceeded,
	}
}

func TestScopeFromScans_CompleteWhenAllComplete(t *testing.T) {
	now := time.Now().UTC()
	s := scopeFromScans([]model.Scan{
		{ID: "a", Collector: "mcp", GenerationID: "g1", CoverageStatus: ingest.StatusComplete, CompletedAt: &now, StageStates: okStages()},
		{ID: "b", Collector: "config", GenerationID: "g2", CoverageStatus: ingest.StatusComplete, StageStates: okStages()},
	})
	if !s.Completeness.Complete {
		t.Error("all-complete scopes must be complete")
	}
	if len(s.GenerationIDs) != 2 {
		t.Errorf("expected 2 generation ids, got %v", s.GenerationIDs)
	}
	if s.Completeness.CompletedAt == nil {
		t.Error("expected a completed_at to be surfaced")
	}
}

// TestScopeFromScans_IncompleteWhenStageFailed is the F4 counterexample: a
// coverage-complete promoted generation whose snapshot stage FAILED must NOT be
// reported complete — coverage-complete alone is not sufficient; the
// prerequisite ingest stages must have succeeded.
func TestScopeFromScans_IncompleteWhenStageFailed(t *testing.T) {
	failed := okStages()
	failed[ingest.StageSnapshot] = ingest.StageFailed
	s := scopeFromScans([]model.Scan{
		{ID: "a", Collector: "mcp", GenerationID: "g1", CoverageStatus: ingest.StatusComplete, StageStates: failed},
	})
	if s.Completeness.Complete {
		t.Error("a coverage-complete scope with a failed prerequisite stage must not be complete")
	}
}

// TestScopeFromScans_IncompleteWhenStageStatesMissing guards the durability
// contract: a promoted generation with NO recorded stage states cannot be
// confirmed complete (F4 records prerequisites before promotion, so a missing
// set means an unverifiable pointer).
func TestScopeFromScans_IncompleteWhenStageStatesMissing(t *testing.T) {
	s := scopeFromScans([]model.Scan{
		{ID: "a", Collector: "mcp", GenerationID: "g1", CoverageStatus: ingest.StatusComplete},
	})
	if s.Completeness.Complete {
		t.Error("a scope with no recorded stage states must not be complete")
	}
}

func TestScopeFromScans_PartialDowngrades(t *testing.T) {
	s := scopeFromScans([]model.Scan{
		{ID: "a", Collector: "mcp", GenerationID: "g1", CoverageStatus: ingest.StatusComplete},
		{ID: "b", Collector: "a2a", GenerationID: "g2", CoverageStatus: ingest.StatusPartial, Error: "target x timeout"},
	})
	if s.Completeness.Complete {
		t.Error("a partial scope must not be complete")
	}
	if s.Completeness.CoverageStatus != string(ingest.StatusPartial) {
		t.Errorf("coverage_status = %q, want partial", s.Completeness.CoverageStatus)
	}
	if len(s.Completeness.SourceErrors) != 1 {
		t.Errorf("expected one source error, got %v", s.Completeness.SourceErrors)
	}
}

func TestScopeFromScans_ExposesPerGenerationStageOutcomes(t *testing.T) {
	// F4: API completeness must disclose the per-generation stage outcomes,
	// not just a rolled-up boolean. A scope whose post-processing stage is
	// partial must be visible field-by-field even while the scope is current.
	s := scopeFromScans([]model.Scan{
		{
			ID: "a", Collector: "mcp", Scope: "mcp", GenerationID: "g1",
			CoverageStatus: ingest.StatusComplete,
			StageStates: map[string]ingest.StageState{
				ingest.StageWrite:          ingest.StageSucceeded,
				ingest.StagePostProcessing: ingest.StagePartial,
				ingest.StageSnapshot:       ingest.StageSucceeded,
				ingest.StagePromotion:      ingest.StageSucceeded,
			},
		},
	})
	if len(s.Completeness.Generations) != 1 {
		t.Fatalf("expected one per-generation outcome, got %d", len(s.Completeness.Generations))
	}
	g := s.Completeness.Generations[0]
	if g.GenerationID != "g1" || g.Collector != "mcp" || g.Scope != "mcp" {
		t.Errorf("unexpected generation identity: %+v", g)
	}
	if g.StageStates[ingest.StagePostProcessing] != ingest.StagePartial {
		t.Errorf("post-processing stage should be disclosed as partial, got %q",
			g.StageStates[ingest.StagePostProcessing])
	}
	if g.CoverageStatus != string(ingest.StatusComplete) {
		t.Errorf("coverage_status = %q, want complete", g.CoverageStatus)
	}
}

// TestApplyDeleteBlockers_DeleteFailedScopeBlocksCompleteness is the
// delete-lifecycle counterexample: one HEALTHY complete scope plus one current
// scope stuck in 'delete_failed'. The delete_failed scope is excluded from
// CurrentGenerations (so scopeFromScans would report complete), but it must be
// folded back in as a completeness blocker + source error rather than silently
// dropped and reported all-clear.
func TestApplyDeleteBlockers_DeleteFailedScopeBlocksCompleteness(t *testing.T) {
	// A healthy, complete scope: on its own this rolls up to complete.
	healthy := scopeFromScans([]model.Scan{
		{ID: "healthy", Collector: "mcp", Scope: "mcp", GenerationID: "g1",
			CoverageStatus: ingest.StatusComplete, StageStates: okStages()},
	})
	if !healthy.Completeness.Complete {
		t.Fatal("precondition: the healthy scope alone must be complete")
	}

	// The delete_failed scope is still is_current (its flag survives until the
	// delete finishes), so CurrentGenerations excludes it but it must surface.
	deleting := []model.Scan{
		{ID: "wip", Collector: "config", Scope: "config", GenerationID: "g2",
			DeleteState: model.DeleteStateFailed},
	}

	got := applyDeleteBlockers(healthy, deleting)
	if got.Completeness.Complete {
		t.Error("a scope stuck in delete_failed must force the posture incomplete")
	}
	if len(got.Completeness.SourceErrors) != 1 {
		t.Fatalf("expected one delete source error, got %v", got.Completeness.SourceErrors)
	}
	msg := got.Completeness.SourceErrors[0]
	if !contains(msg, string(model.DeleteStateFailed)) || !contains(msg, "wip") || !contains(msg, "config") {
		t.Errorf("source error should name the scope, state, and scan id; got %q", msg)
	}
	// The healthy scope's generation must still be present in scope.
	if len(got.GenerationIDs) != 1 || got.GenerationIDs[0] != "g1" {
		t.Errorf("healthy generation must remain in scope, got %v", got.GenerationIDs)
	}
}

// TestApplyDeleteBlockers_NoDeletingScopesPassThrough confirms the no-op path:
// with no delete-lifecycle scopes, completeness is unchanged.
func TestApplyDeleteBlockers_NoDeletingScopesPassThrough(t *testing.T) {
	healthy := scopeFromScans([]model.Scan{
		{ID: "healthy", Collector: "mcp", Scope: "mcp", GenerationID: "g1",
			CoverageStatus: ingest.StatusComplete, StageStates: okStages()},
	})
	got := applyDeleteBlockers(healthy, nil)
	if !got.Completeness.Complete {
		t.Error("with no deleting scopes the healthy posture must remain complete")
	}
	if len(got.Completeness.SourceErrors) != 0 {
		t.Errorf("expected no source errors, got %v", got.Completeness.SourceErrors)
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

func TestScopeFromScans_MissingGenerationIDNotComplete(t *testing.T) {
	// A row marked current but carrying no generation id cannot be
	// authoritative — completeness must stay false.
	s := scopeFromScans([]model.Scan{
		{ID: "a", Collector: "mcp", CoverageStatus: ingest.StatusComplete},
	})
	if s.Completeness.Complete {
		t.Error("a current row without a generation id must not be complete")
	}
}

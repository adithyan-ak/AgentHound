package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

// generationLister exposes the current (promoted) generations used to scope
// default reads and derive completeness. *appdb.ScanStore satisfies it.
type generationLister interface {
	CurrentGenerations(ctx context.Context) ([]model.Scan, error)
	// CurrentDeletingGenerations returns is_current scopes whose durable delete
	// is in progress or failed. CurrentGenerations excludes them, so without
	// surfacing them here a scope stuck mid-delete would silently vanish and the
	// remaining scopes could roll up to "complete". They are disclosed as
	// completeness blockers / source errors instead.
	CurrentDeletingGenerations(ctx context.Context) ([]model.Scan, error)
}

// generationScope is the resolved current-generation gate for a request: the
// set of promoted generation ids and the completeness metadata derived from
// their coverage. Default reads scope to GenerationIDs and disclose
// Completeness so staged/non-current generations are never surfaced as clean.
type generationScope struct {
	GenerationIDs []string
	Completeness  Completeness
}

// resolveGenerationScope reads the current generations and derives the scope.
// A nil store yields an empty, unknown scope (completeness "none") so callers
// without a Postgres store degrade honestly rather than fabricating an
// all-clear view.
func resolveGenerationScope(ctx context.Context, store generationLister) (generationScope, error) {
	if store == nil {
		return generationScope{Completeness: Completeness{CoverageStatus: "none"}}, nil
	}
	scans, err := store.CurrentGenerations(ctx)
	if err != nil {
		return generationScope{}, err
	}
	deleting, err := store.CurrentDeletingGenerations(ctx)
	if err != nil {
		return generationScope{}, err
	}
	return applyDeleteBlockers(scopeFromScans(scans), deleting), nil
}

// applyDeleteBlockers folds current scopes stuck in a delete lifecycle into the
// completeness verdict. A current scope whose durable delete is in progress or
// failed is neither cleanly present (it is being torn down) nor cleanly gone
// (its is_current row survives until the delete completes), so the overall
// posture cannot be reported complete: it is forced incomplete and each such
// scope is disclosed as a source error. This is the alternative to silently
// excluding them, which could let the remaining scopes roll up to all-clear
// while a delete is unresolved.
func applyDeleteBlockers(scope generationScope, deleting []model.Scan) generationScope {
	if len(deleting) == 0 {
		return scope
	}
	scope.Completeness.Complete = false
	for i := range deleting {
		d := deleting[i]
		label := d.Scope
		if label == "" {
			label = d.Collector
		}
		state := string(d.DeleteState)
		if state == "" {
			state = "deleting"
		}
		scope.Completeness.SourceErrors = append(scope.Completeness.SourceErrors,
			fmt.Sprintf("%s: scan delete %s (%s)", label, state, d.ID))
	}
	return scope
}

// scopeFromScans builds the generation scope from the promoted scans. It is
// separated from the store read so it is unit-testable without a database.
func scopeFromScans(scans []model.Scan) generationScope {
	if len(scans) == 0 {
		return generationScope{Completeness: Completeness{CoverageStatus: "none"}}
	}

	seen := make(map[string]struct{}, len(scans))
	var gens []string
	statuses := make([]ingest.CollectionStatus, 0, len(scans))
	var errs []string
	var capturedAt, completedAt *time.Time
	var stageOutcomes []GenerationStageOutcome

	for i := range scans {
		s := scans[i]
		if s.GenerationID != "" {
			if _, ok := seen[s.GenerationID]; !ok {
				seen[s.GenerationID] = struct{}{}
				gens = append(gens, s.GenerationID)
			}
		}
		cs := s.CoverageStatus
		if !cs.Valid() {
			cs = ingest.StatusUnknown
		}
		statuses = append(statuses, cs)
		if s.Error != "" {
			errs = append(errs, s.Collector+": "+s.Error)
		}
		capturedAt = laterTime(capturedAt, s.CapturedAt)
		completedAt = laterTime(completedAt, s.CompletedAt)
		// Per-generation stage outcomes: disclose exactly which ingest stages
		// this promoted scope completed, so completeness is auditable beyond
		// the rolled-up boolean.
		stageOutcomes = append(stageOutcomes, GenerationStageOutcome{
			GenerationID:   s.GenerationID,
			Collector:      s.Collector,
			Scope:          s.Scope,
			CoverageStatus: string(cs),
			StageStates:    s.StageStates,
		})
	}

	rollup := ingest.RollupStatus(statuses...)
	// A scope with no promoted generation ids cannot be authoritative even if
	// a row was is_current, so completeness is gated on having generation ids.
	// It is ALSO gated on every promoted generation's prerequisite stages
	// having succeeded (F4): coverage-complete alone is not enough — if the
	// write, post-processing, or snapshot stage of a promoted generation did
	// not succeed, the persisted findings/graph do not fully back the coverage
	// claim, so the scope is disclosed as incomplete.
	complete := len(gens) > 0 && rollup == ingest.StatusComplete && allStagesSucceeded(scans)

	return generationScope{
		GenerationIDs: gens,
		Completeness: Completeness{
			Complete:       complete,
			CoverageStatus: string(rollup),
			GenerationIDs:  gens,
			CapturedAt:     capturedAt,
			CompletedAt:    completedAt,
			SourceErrors:   errs,
			Generations:    stageOutcomes,
		},
	}
}

// allStagesSucceeded reports whether every promoted generation recorded
// successful prerequisite stages: write strictly succeeded, and post-processing
// and snapshot each succeeded or were legitimately skipped. A generation with a
// missing/failed/partial prerequisite stage means the promoted view is not
// fully backed by the graph + persisted findings, so the scope is not complete.
func allStagesSucceeded(scans []model.Scan) bool {
	for i := range scans {
		st := scans[i].StageStates
		if st == nil {
			return false
		}
		if st[ingest.StageWrite] != ingest.StageSucceeded {
			return false
		}
		if !stagePrereqOK(st[ingest.StagePostProcessing]) {
			return false
		}
		if !stagePrereqOK(st[ingest.StageSnapshot]) {
			return false
		}
	}
	return true
}

// stagePrereqOK reports whether a prerequisite stage state clears the
// completeness gate: succeeded or legitimately skipped.
func stagePrereqOK(s ingest.StageState) bool {
	return s == ingest.StageSucceeded || s == ingest.StageSkipped
}

func laterTime(a, b *time.Time) *time.Time {
	if b == nil {
		return a
	}
	if a == nil || b.After(*a) {
		return b
	}
	return a
}

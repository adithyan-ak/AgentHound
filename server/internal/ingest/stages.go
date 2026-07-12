package ingest

import sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"

// stageOrder is the canonical order stages are reported in, matching the
// ingest sequence (write → post-processing → snapshot → promotion).
var stageOrder = []string{
	sdkingest.StageWrite,
	sdkingest.StagePostProcessing,
	sdkingest.StageSnapshot,
	sdkingest.StagePromotion,
}

// stageTracker accumulates the independent outcome of each ingest stage so a
// failure in one stage is neither masked by another's success nor collapsed
// into 0/0 success-like history.
type stageTracker struct {
	states map[string]sdkingest.StageState
	errs   map[string]string
}

func newStageTracker() *stageTracker {
	return &stageTracker{
		states: make(map[string]sdkingest.StageState, len(stageOrder)),
		errs:   make(map[string]string, len(stageOrder)),
	}
}

// set records the outcome of a stage. A non-nil err is captured for the
// StageResult only when the state is not success.
func (t *stageTracker) set(name string, state sdkingest.StageState, err error) {
	t.states[name] = state
	if err != nil && state != sdkingest.StageSucceeded {
		t.errs[name] = err.Error()
	}
}

func (t *stageTracker) state(name string) sdkingest.StageState { return t.states[name] }

// stageOK reports whether a stage state satisfies the promotion gate: a stage
// is "OK" when it either succeeded or was legitimately skipped (e.g. no graph
// database or no finding store configured). Failed and partial are NOT OK — a
// generation with any failed/partial required stage is never promoted.
func stageOK(state sdkingest.StageState) bool {
	return state == sdkingest.StageSucceeded || state == sdkingest.StageSkipped
}

// snapshot returns the per-stage state map for persistence.
func (t *stageTracker) snapshot() map[string]sdkingest.StageState {
	out := make(map[string]sdkingest.StageState, len(t.states))
	for k, v := range t.states {
		out[k] = v
	}
	return out
}

// results returns the ordered per-stage results for the IngestResult.
func (t *stageTracker) results() []sdkingest.StageResult {
	var out []sdkingest.StageResult
	for _, name := range stageOrder {
		state, ok := t.states[name]
		if !ok {
			continue
		}
		out = append(out, sdkingest.StageResult{
			Name:  name,
			State: state,
			Error: t.errs[name],
		})
	}
	return out
}

// rollup derives the artifact-level ingest status from the per-stage states.
// The write stage is decisive: a failed write means nothing trustworthy was
// committed; a partial write, or any downstream stage failure, is partial.
func (t *stageTracker) rollup() sdkingest.CollectionStatus {
	switch t.states[sdkingest.StageWrite] {
	case sdkingest.StageFailed:
		return sdkingest.StatusFailed
	case sdkingest.StagePartial:
		return sdkingest.StatusPartial
	}
	for _, name := range stageOrder {
		if t.states[name] == sdkingest.StageFailed {
			return sdkingest.StatusPartial
		}
	}
	return sdkingest.StatusComplete
}

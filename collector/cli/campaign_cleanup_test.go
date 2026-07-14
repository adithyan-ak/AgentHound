package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

type runCleanupRecorder struct {
	id       string
	state    *module.FileStatefulModule
	calls    *[]string
	failOnce map[string]bool
}

func (m *runCleanupRecorder) ID() string            { return m.id }
func (m *runCleanupRecorder) Action() action.Action { return action.Poison }
func (m *runCleanupRecorder) Target() string        { return m.id + "-target" }
func (m *runCleanupRecorder) Description() string   { return "run cleanup recorder" }
func (m *runCleanupRecorder) Version() string       { return "0.0.0" }
func (m *runCleanupRecorder) IsDestructive() bool   { return true }
func (m *runCleanupRecorder) Stateful() module.StatefulModule {
	return m.state
}
func (m *runCleanupRecorder) Poison(context.Context, action.Target, action.PoisonPayload) (*action.PoisonReceipt, error) {
	return nil, nil
}
func (m *runCleanupRecorder) Revert(_ context.Context, receipt action.Receipt) error {
	targetID := ""
	switch value := receipt.(type) {
	case *action.PoisonReceipt:
		targetID = value.TargetID
	case *action.ImplantReceipt:
		targetID = value.TargetID
	}
	*m.calls = append(*m.calls, targetID)
	if m.failOnce[targetID] {
		delete(m.failOnce, targetID)
		return action.ErrRevertConflict
	}
	return nil
}

func writeRunImplantReceipt(
	t *testing.T,
	state module.StatefulModule,
	engagementID string,
	runID string,
	sequence uint64,
	targetID string,
) {
	t.Helper()
	if _, err := state.WriteReceipt(engagementID, &action.ImplantReceipt{
		ModuleID: "test", EngagementID: engagementID,
		CampaignRunID: runID, StepSequence: sequence,
		TargetID: targetID,
	}); err != nil {
		t.Fatal(err)
	}
}

func registerRunCleanupRecorder(
	t *testing.T,
	id string,
	calls *[]string,
) *runCleanupRecorder {
	t.Helper()
	recorder := &runCleanupRecorder{
		id: id, state: module.NewFileStatefulModule(id),
		calls: calls, failOnce: map[string]bool{},
	}
	module.Register(recorder)
	t.Cleanup(func() { deregisterModule(t, id) })
	return recorder
}

func writeRunReceipt(
	t *testing.T,
	state module.StatefulModule,
	engagementID string,
	runID string,
	sequence uint64,
	targetID string,
) {
	t.Helper()
	if _, err := state.WriteReceipt(engagementID, &action.PoisonReceipt{
		ModuleID: "test", EngagementID: engagementID,
		CampaignRunID: runID, StepSequence: sequence,
		TargetID: targetID,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupCampaignRunOrdersGloballyAndIsolatesRuns(t *testing.T) {
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	var calls []string
	first := registerRunCleanupRecorder(t, "test.cleanup.global.a", &calls)
	second := registerRunCleanupRecorder(t, "test.cleanup.global.b", &calls)
	writeRunReceipt(t, first.state, "ENG-RUN", "run-a", 1, "step-1")
	writeRunImplantReceipt(t, second.state, "ENG-RUN", "run-a", 3, "step-3")
	writeRunReceipt(t, first.state, "ENG-RUN", "run-b", 2, "other-run")

	result := cleanupCampaignRun(context.Background(), "ENG-RUN", "run-a")
	if result.Status != campaign.CleanupRestored || result.ReceiptsSelected != 2 {
		t.Fatalf("cleanup result = %+v", result)
	}
	want := []string{"step-3", "step-1"}
	if !equalStringSlices(calls, want) {
		t.Fatalf("cleanup order = %v, want %v", calls, want)
	}
}

func TestCleanupCampaignRunRejectsInvalidSequenceBeforeWrites(t *testing.T) {
	for _, test := range []struct {
		name      string
		sequences []uint64
	}{
		{name: "missing", sequences: []uint64{0}},
		{name: "duplicate", sequences: []uint64{2, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))
			var calls []string
			first := registerRunCleanupRecorder(t, "test.cleanup.invalid."+test.name+".a", &calls)
			second := registerRunCleanupRecorder(t, "test.cleanup.invalid."+test.name+".b", &calls)
			writeRunReceipt(t, first.state, "ENG-INVALID", "run-invalid", test.sequences[0], "first")
			if len(test.sequences) > 1 {
				writeRunReceipt(t, second.state, "ENG-INVALID", "run-invalid", test.sequences[1], "second")
			}
			result := cleanupCampaignRun(context.Background(), "ENG-INVALID", "run-invalid")
			if result.Status != campaign.CleanupIndeterminate ||
				result.FailureCode != "invalid_sequence_metadata" {
				t.Fatalf("cleanup result = %+v", result)
			}
			if len(calls) != 0 {
				t.Fatalf("invalid sequence dispatched cleanup: %v", calls)
			}
		})
	}
}

func TestCleanupCampaignRunFailStopsAndRetriesImmutableReceipts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	t.Setenv("AGENTHOUND_STATE_DIR", root)
	var calls []string
	first := registerRunCleanupRecorder(t, "test.cleanup.retry.a", &calls)
	second := registerRunCleanupRecorder(t, "test.cleanup.retry.b", &calls)
	second.failOnce["step-2"] = true
	writeRunReceipt(t, first.state, "ENG-RETRY", "run-retry", 3, "step-3")
	writeRunReceipt(t, second.state, "ENG-RETRY", "run-retry", 2, "step-2")
	writeRunReceipt(t, first.state, "ENG-RETRY", "run-retry", 1, "step-1")

	beforeFirst, err := os.ReadFile(filepath.Join(first.state.StateDir(), "ENG-RETRY.json"))
	if err != nil {
		t.Fatal(err)
	}
	beforeSecond, err := os.ReadFile(filepath.Join(second.state.StateDir(), "ENG-RETRY.json"))
	if err != nil {
		t.Fatal(err)
	}

	result := cleanupCampaignRun(context.Background(), "ENG-RETRY", "run-retry")
	if result.Status != campaign.CleanupConflict {
		t.Fatalf("first cleanup = %+v", result)
	}
	if want := []string{"step-3", "step-2"}; !equalStringSlices(calls, want) {
		t.Fatalf("fail-stop calls = %v, want %v", calls, want)
	}

	calls = nil
	result = cleanupCampaignRun(context.Background(), "ENG-RETRY", "run-retry")
	if result.Status != campaign.CleanupRestored {
		t.Fatalf("retry cleanup = %+v", result)
	}
	if want := []string{"step-3", "step-2", "step-1"}; !equalStringSlices(calls, want) {
		t.Fatalf("retry calls = %v, want %v", calls, want)
	}

	afterFirst, _ := os.ReadFile(filepath.Join(first.state.StateDir(), "ENG-RETRY.json"))
	afterSecond, _ := os.ReadFile(filepath.Join(second.state.StateDir(), "ENG-RETRY.json"))
	if string(beforeFirst) != string(afterFirst) || string(beforeSecond) != string(afterSecond) {
		t.Fatal("run cleanup modified immutable receipt files")
	}
}

func equalStringSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

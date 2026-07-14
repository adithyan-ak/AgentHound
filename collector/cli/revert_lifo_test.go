package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

// lifoRecorder is a minimal Poisoner/Reverter that records the order in
// which the CLI hands it receipts, so we can assert `agenthound revert`
// walks each module's append-ordered receipt file newest-first (LIFO).
type lifoRecorder struct {
	id       string
	state    *module.FileStatefulModule
	reverted []string
}

func (m *lifoRecorder) ID() string            { return m.id }
func (m *lifoRecorder) Action() action.Action { return action.Poison }
func (m *lifoRecorder) Target() string        { return m.id + "-target" }
func (m *lifoRecorder) Description() string   { return "lifo recorder" }
func (m *lifoRecorder) Version() string       { return "0.0.0" }
func (m *lifoRecorder) IsDestructive() bool   { return true }
func (m *lifoRecorder) Stateful() module.StatefulModule {
	return m.state
}
func (m *lifoRecorder) Poison(ctx context.Context, t action.Target, payload action.PoisonPayload) (*action.PoisonReceipt, error) {
	return nil, nil
}
func (m *lifoRecorder) Revert(ctx context.Context, receipt action.Receipt) error {
	if r, ok := receipt.(*action.PoisonReceipt); ok {
		m.reverted = append(m.reverted, r.TargetID)
	}
	return nil
}

// TestRunRevert_PerFileLIFO asserts revert dispatches a module's receipts
// newest-first (reverse of the append-ordered file).
func TestRunRevert_PerFileLIFO(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))

	rec := &lifoRecorder{
		id:    "mock.lifo.order.poison",
		state: module.NewFileStatefulModule("mock.lifo.order.poison"),
	}
	module.Register(rec)
	defer deregisterModule(t, rec.ID())

	// Append receipts oldest -> newest, matching the file's append order.
	for index, tid := range []string{"first", "second", "third"} {
		runID := ""
		sequence := uint64(0)
		if index > 0 {
			runID = "campaign-run"
			sequence = uint64(index)
		}
		if _, err := rec.state.WriteReceipt("ENG-LIFO-ORDER", &action.PoisonReceipt{
			ModuleID:      rec.ID(),
			EngagementID:  "ENG-LIFO-ORDER",
			CampaignRunID: runID,
			StepSequence:  sequence,
			TargetID:      tid,
			DryRun:        false,
		}); err != nil {
			t.Fatalf("write receipt %s: %v", tid, err)
		}
	}

	out := &bytes.Buffer{}
	cmd := newRevertTestCmd(out)
	if err := runRevert(cmd, []string{"ENG-LIFO-ORDER"}); err != nil {
		t.Fatalf("runRevert: %v", err)
	}

	want := []string{"third", "second", "first"} // newest first
	if len(rec.reverted) != len(want) {
		t.Fatalf("reverted %v, want %v", rec.reverted, want)
	}
	for i := range want {
		if rec.reverted[i] != want[i] {
			t.Fatalf("revert order = %v, want %v (LIFO)", rec.reverted, want)
		}
	}
}

func TestRunRevertBestEffortContinuesAcrossModules(t *testing.T) {
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	failing := &conflictReverter{
		id:    "mock.aaa.engagement.failure",
		state: module.NewFileStatefulModule("mock.aaa.engagement.failure"),
	}
	success := &lifoRecorder{
		id:    "mock.zzz.engagement.success",
		state: module.NewFileStatefulModule("mock.zzz.engagement.success"),
	}
	module.Register(failing)
	module.Register(success)
	defer deregisterModule(t, failing.ID())
	defer deregisterModule(t, success.ID())
	if _, err := failing.state.WriteReceipt("ENG-BEST-EFFORT", &action.PoisonReceipt{
		ModuleID: failing.ID(), EngagementID: "ENG-BEST-EFFORT",
		CampaignRunID: "run-tagged", StepSequence: 2, TargetID: "fails",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := success.state.WriteReceipt("ENG-BEST-EFFORT", &action.PoisonReceipt{
		ModuleID: success.ID(), EngagementID: "ENG-BEST-EFFORT",
		TargetID: "legacy-succeeds",
	}); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	err := runRevert(newRevertTestCmd(out), []string{"ENG-BEST-EFFORT"})
	if err == nil {
		t.Fatal("engagement recovery must aggregate the failing module")
	}
	if len(success.reverted) != 1 || success.reverted[0] != "legacy-succeeds" {
		t.Fatalf("best-effort recovery did not continue: %v", success.reverted)
	}
}

// TestRunRevert_RetainsReceiptsAndFailsOnConflict confirms that when a
// Reverter reports a conflict/indeterminate error the command exits
// nonzero, reports INCOMPLETE, and leaves the receipts on disk for retry.
func TestRunRevert_RetainsReceiptsAndFailsOnConflict(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))

	rec := &conflictReverter{
		id:    "mock.conflict.poison",
		state: module.NewFileStatefulModule("mock.conflict.poison"),
	}
	module.Register(rec)
	defer deregisterModule(t, rec.ID())

	if _, err := rec.state.WriteReceipt("ENG-CONFLICT", &action.PoisonReceipt{
		ModuleID:     rec.ID(),
		EngagementID: "ENG-CONFLICT",
		TargetID:     "tool-1",
		DryRun:       false,
	}); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	out := &bytes.Buffer{}
	cmd := newRevertTestCmd(out)
	err := runRevert(cmd, []string{"ENG-CONFLICT"})
	if err == nil {
		t.Fatal("expected nonzero exit (error) when a revert conflicts")
	}
	if !bytes.Contains(out.Bytes(), []byte("INCOMPLETE")) {
		t.Errorf("expected INCOMPLETE report, got: %s", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("receipts retained")) {
		t.Errorf("expected retention note, got: %s", out.String())
	}

	// Receipts must still be readable after a failed revert.
	receipts, rerr := rec.state.ReadReceipts("ENG-CONFLICT")
	if rerr != nil {
		t.Fatalf("ReadReceipts after failed revert: %v", rerr)
	}
	if len(receipts) != 1 {
		t.Errorf("expected receipt retained after failed revert, got %d", len(receipts))
	}
}

// conflictReverter always reports a conflict, standing in for a
// conflict-aware module Reverter without needing a live target.
type conflictReverter struct {
	id    string
	state *module.FileStatefulModule
}

func (m *conflictReverter) ID() string            { return m.id }
func (m *conflictReverter) Action() action.Action { return action.Poison }
func (m *conflictReverter) Target() string        { return m.id + "-target" }
func (m *conflictReverter) Description() string   { return "conflict reverter" }
func (m *conflictReverter) Version() string       { return "0.0.0" }
func (m *conflictReverter) IsDestructive() bool   { return true }
func (m *conflictReverter) Stateful() module.StatefulModule {
	return m.state
}
func (m *conflictReverter) Poison(ctx context.Context, t action.Target, payload action.PoisonPayload) (*action.PoisonReceipt, error) {
	return nil, nil
}
func (m *conflictReverter) Revert(ctx context.Context, receipt action.Receipt) error {
	return errConflict
}

var errConflict = errRevertConflict{}

type errRevertConflict struct{}

func (errRevertConflict) Error() string { return "refusing to overwrite (conflict)" }

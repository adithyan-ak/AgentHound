package ingest

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testExecution(t *testing.T) *ScanExecution {
	t.Helper()
	started := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	execution := NewScanExecution(ScanModeActive, true, started)
	execution.Actions = append(execution.Actions, ActionRecord{
		ID:          "action-1",
		Action:      "probe",
		TargetID:    "target-1",
		PathNodeIDs: []string{"node-1", "node-2"},
		Status:      ActionSucceeded,
		Outcome:     "credential_access_observed",
		StartedAt:   started.Format(time.RFC3339),
		CompletedAt: started.Add(time.Second).Format(time.RFC3339),
	})
	execution.UpdatedAt = started.Add(time.Second).Format(time.RFC3339)
	execution.RecomputeSummary()
	return execution
}

func TestSetGetScanExecutionStrictRoundTrip(t *testing.T) {
	execution := testExecution(t)
	meta := IngestMeta{Extra: map[string]any{"keep": "value"}}
	if err := SetScanExecution(&meta, execution); err != nil {
		t.Fatal(err)
	}

	got, present, err := GetScanExecution(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !present || got.Version != ScanExecutionVersion || got.Mode != ScanModeActive || !got.Deep {
		t.Fatalf("scan execution was not preserved: present=%t value=%+v", present, got)
	}
	if got.Summary.ActionsAttempted != 1 || got.Summary.ActionsSucceeded != 1 {
		t.Fatalf("summary = %+v", got.Summary)
	}
	if meta.Extra["keep"] != "value" {
		t.Fatal("SetScanExecution discarded unrelated metadata")
	}
}

func TestScanExecutionAlwaysEncodesArrays(t *testing.T) {
	execution := NewScanExecution(ScanModeStealth, false, time.Now())
	document, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(document)
	if !strings.Contains(jsonText, `"actions":[]`) || !strings.Contains(jsonText, `"recovery":[]`) ||
		!strings.Contains(jsonText, `"exclusions":[]`) {
		t.Fatalf("top-level arrays encoded as null: %s", document)
	}

	action := ActionRecord{PathNodeIDs: nil}
	document, err = json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"path_node_ids":[]`) {
		t.Fatalf("path_node_ids encoded as null: %s", document)
	}
	recovery := RecoveryRecord{CredentialIDs: nil}
	document, err = json.Marshal(recovery)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"credential_ids":[]`) {
		t.Fatalf("credential_ids encoded as null: %s", document)
	}
}

func TestScanExecutionPreservesExclusions(t *testing.T) {
	execution := testExecution(t)
	execution.Exclusions = []string{"blocked.example", "10.20.0.0/16"}
	meta := IngestMeta{}
	if err := SetScanExecution(&meta, execution); err != nil {
		t.Fatal(err)
	}
	got, present, err := GetScanExecution(meta)
	if err != nil || !present {
		t.Fatalf("GetScanExecution = (%+v, %t, %v)", got, present, err)
	}
	if !reflect.DeepEqual(got.Exclusions, execution.Exclusions) {
		t.Fatalf("exclusions = %v, want %v", got.Exclusions, execution.Exclusions)
	}
}

func TestDecodeScanExecutionRejectsUnknownNestedField(t *testing.T) {
	execution := testExecution(t)
	document, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	document = []byte(strings.Replace(string(document), `"target_id":"target-1"`, `"target_id":"target-1","surprise":true`, 1))
	_, err = DecodeScanExecution(document)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown-field rejection", err)
	}
}

func TestDecodeScanExecutionRejectsNullArrays(t *testing.T) {
	execution := testExecution(t)
	document, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	document = []byte(strings.Replace(string(document), `"path_node_ids":["node-1","node-2"]`, `"path_node_ids":null`, 1))
	_, err = DecodeScanExecution(document)
	if err == nil || !strings.Contains(err.Error(), "must be an array") {
		t.Fatalf("error = %v, want null-array rejection", err)
	}
}

func TestScanExecutionValidateRejectsReferencesAndStaleSummary(t *testing.T) {
	execution := testExecution(t)
	execution.Actions[0].RecoveryID = "missing"
	if err := execution.Validate(); err == nil || !strings.Contains(err.Error(), "does not reference recovery") {
		t.Fatalf("error = %v, want invalid recovery reference", err)
	}

	execution = testExecution(t)
	execution.Summary = ExecutionSummary{}
	if err := execution.Validate(); err == nil || !strings.Contains(err.Error(), "summary does not match") {
		t.Fatalf("error = %v, want stale-summary rejection", err)
	}
}

func TestRecomputeSummaryCountsAttemptedSkippedAndUnresolvedRecovery(t *testing.T) {
	execution := testExecution(t)
	execution.Actions = append(execution.Actions,
		ActionRecord{Status: ActionRunning},
		ActionRecord{Status: ActionFailed},
		ActionRecord{Status: ActionBlocked},
		ActionRecord{Status: ActionSkipped},
	)
	execution.Recovery = []RecoveryRecord{
		{Status: RecoveryPrepared},
		{Status: RecoveryApplied},
		{Status: RecoveryRestored},
		{Status: RecoveryConflict},
		{Status: RecoveryIndeterminate},
		{Status: RecoveryFailed},
	}
	execution.RecomputeSummary()
	want := ExecutionSummary{
		ActionsAttempted: 3,
		ActionsSucceeded: 1,
		ActionsFailed:    1,
		ActionsSkipped:   2,
		CleanupFailures:  5,
	}
	if execution.Summary != want {
		t.Fatalf("summary = %+v, want %+v", execution.Summary, want)
	}
}

func TestJournalLifecycleCheckpointsEveryTransition(t *testing.T) {
	execution := testExecution(t)
	checkpoints := 0
	journal, err := NewJournal(execution, func(got *ScanExecution) error {
		checkpoints++
		return got.Validate()
	})
	if err != nil {
		t.Fatal(err)
	}
	journal.now = func() time.Time {
		return time.Date(2026, 8, 18, 12, 1, 0, 0, time.UTC)
	}

	err = journal.Prepare("action-1", RecoveryRecord{
		ID:            "recovery-1",
		CredentialIDs: []string{},
		Data:          map[string]any{"original": "value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkApplied("recovery-1"); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkRestored("recovery-1"); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 3 {
		t.Fatalf("checkpoints = %d, want 3", checkpoints)
	}
	if execution.Recovery[0].Status != RecoveryRestored || execution.Summary.CleanupFailures != 0 {
		t.Fatalf("execution after recovery = %+v", execution)
	}
}

func TestJournalPropagatesCheckpointFailure(t *testing.T) {
	execution := testExecution(t)
	cause := errors.New("disk full")
	journal, err := NewJournal(execution, func(*ScanExecution) error { return cause })
	if err != nil {
		t.Fatal(err)
	}
	err = journal.Prepare("action-1", RecoveryRecord{ID: "recovery-1", CredentialIDs: []string{}})
	if !errors.Is(err, cause) {
		t.Fatalf("error = %v, want checkpoint cause", err)
	}
}

func TestSetScanExecutionNilRemovesKey(t *testing.T) {
	meta := IngestMeta{Extra: map[string]any{ScanExecutionExtraKey: map[string]any{}, "keep": true}}
	if err := SetScanExecution(&meta, nil); err != nil {
		t.Fatal(err)
	}
	if _, present := meta.Extra[ScanExecutionExtraKey]; present {
		t.Fatal("scan_execution key was not removed")
	}
	if meta.Extra["keep"] != true {
		t.Fatal("unrelated metadata was removed")
	}
}

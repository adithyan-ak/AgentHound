package ingest

import (
	"encoding/json"
	"testing"
)

func TestCollectionStatusValid(t *testing.T) {
	for _, s := range AllCollectionStatuses {
		if !s.Valid() {
			t.Errorf("status %q should be valid", s)
		}
	}
	if CollectionStatus("bogus").Valid() {
		t.Error("bogus status should be invalid")
	}
	if !StatusComplete.IsClean() {
		t.Error("complete must be clean")
	}
	for _, s := range []CollectionStatus{StatusPartial, StatusFailed, StatusUnknown} {
		if s.IsClean() {
			t.Errorf("%q must not be clean", s)
		}
	}
}

func TestRollupStatus(t *testing.T) {
	cases := []struct {
		name string
		in   []CollectionStatus
		want CollectionStatus
	}{
		{"empty", nil, StatusUnknown},
		{"all complete", []CollectionStatus{StatusComplete, StatusComplete}, StatusComplete},
		{"any partial", []CollectionStatus{StatusComplete, StatusPartial}, StatusPartial},
		{"failed among complete downgrades", []CollectionStatus{StatusComplete, StatusFailed}, StatusPartial},
		{"all failed", []CollectionStatus{StatusFailed, StatusFailed}, StatusFailed},
		{"complete plus unknown is partial", []CollectionStatus{StatusComplete, StatusUnknown}, StatusPartial},
		{"all unknown", []CollectionStatus{StatusUnknown, StatusUnknown}, StatusUnknown},
	}
	for _, c := range cases {
		if got := RollupStatus(c.in...); got != c.want {
			t.Errorf("%s: RollupStatus=%q, want %q", c.name, got, c.want)
		}
	}
}

func TestIngestMetaCoverageRoundTrip(t *testing.T) {
	meta := IngestMeta{
		Version:         1,
		Type:            "agenthound-ingest",
		Collector:       "scan",
		ScanID:          "s1",
		SchemaVersion:   CurrentSchemaVersion,
		IdentityVersion: CurrentIdentityVersion,
		Coverage: &CollectionCoverage{
			Status:                StatusPartial,
			ConstituentCollectors: []string{"config", "mcp"},
			Targets:               []TargetOutcome{{Target: "agent-a", Status: StatusFailed, Error: "timeout"}},
			Methods:               []MethodOutcome{{Target: "srv-1", Method: "tools/list", Status: StatusComplete}},
			Rules:                 []RuleManifestEntry{{RuleID: "poison.v1", Version: "1.2.0"}},
			Truncated:             true,
			TruncationReason:      "page cap",
		},
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got IngestMeta
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SchemaVersion != CurrentSchemaVersion || got.IdentityVersion != CurrentIdentityVersion {
		t.Errorf("versions not preserved: %+v", got)
	}
	if got.Coverage == nil || got.Coverage.Status != StatusPartial {
		t.Fatalf("coverage not preserved: %+v", got.Coverage)
	}
	if len(got.Coverage.Targets) != 1 || got.Coverage.Targets[0].Status != StatusFailed {
		t.Errorf("target outcome not preserved: %+v", got.Coverage.Targets)
	}
	if !got.Coverage.Truncated || got.Coverage.TruncationReason != "page cap" {
		t.Errorf("truncation not preserved: %+v", got.Coverage)
	}
}

func TestStageStateValid(t *testing.T) {
	for _, s := range AllStageStates {
		if !s.Valid() {
			t.Errorf("stage state %q should be valid", s)
		}
	}
	if StageState("bogus").Valid() {
		t.Error("bogus stage state should be invalid")
	}
}

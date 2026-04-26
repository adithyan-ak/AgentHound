package analysis

import (
	"strings"
	"testing"
)

func TestBuildRemediation_WithPath(t *testing.T) {
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "agent-1", Properties: map[string]any{"name": "MyAgent"}},
			{ID: "srv-1", Properties: map[string]any{"name": "DevServer"}},
			{ID: "tool-1", Properties: map[string]any{"name": "ReadDB"}},
			{ID: "res-1", Properties: map[string]any{"name": "ProdDB"}},
		},
		Edges: []PathEdge{
			{Source: "agent-1", Target: "srv-1", Kind: "TRUSTS_SERVER"},
			{Source: "srv-1", Target: "tool-1", Kind: "PROVIDES_TOOL"},
			{Source: "tool-1", Target: "res-1", Kind: "HAS_ACCESS_TO"},
		},
	}

	f := &Finding{EdgeKind: "CAN_REACH", SourceID: "agent-1", TargetID: "res-1"}
	steps := BuildRemediation(path, f)

	if len(steps) != 3 {
		t.Fatalf("got %d steps, want 3", len(steps))
	}

	wantEdgeKinds := []string{"TRUSTS_SERVER", "PROVIDES_TOOL", "HAS_ACCESS_TO"}
	for i, wantKind := range wantEdgeKinds {
		if steps[i].EdgeKind != wantKind {
			t.Errorf("steps[%d].EdgeKind = %q, want %q", i, steps[i].EdgeKind, wantKind)
		}
		if steps[i].Step != i+1 {
			t.Errorf("steps[%d].Step = %d, want %d", i, steps[i].Step, i+1)
		}
	}

	if !strings.Contains(steps[0].Description, "MyAgent") {
		t.Errorf("step 0 Description = %q, expected to mention source node name", steps[0].Description)
	}
}

func TestBuildRemediation_DuplicateEdgeKinds(t *testing.T) {
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "a1", Properties: map[string]any{"name": "Agent1"}},
			{ID: "s1", Properties: map[string]any{"name": "Server1"}},
			{ID: "s2", Properties: map[string]any{"name": "Server2"}},
		},
		Edges: []PathEdge{
			{Source: "a1", Target: "s1", Kind: "TRUSTS_SERVER"},
			{Source: "a1", Target: "s2", Kind: "TRUSTS_SERVER"},
		},
	}

	f := &Finding{EdgeKind: "CAN_REACH", SourceID: "a1", TargetID: "s2"}
	steps := BuildRemediation(path, f)

	if len(steps) != 1 {
		t.Fatalf("got %d steps, want 1 (deduped TRUSTS_SERVER)", len(steps))
	}
	if steps[0].EdgeKind != "TRUSTS_SERVER" {
		t.Errorf("EdgeKind = %q, want TRUSTS_SERVER", steps[0].EdgeKind)
	}
}

func TestBuildRemediation_NilPath(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_EXECUTE",
		SourceID:   "tool-1",
		SourceName: "RunCode",
		TargetID:   "host-1",
		TargetName: "prod-server",
	}

	steps := BuildRemediation(nil, f)
	if steps == nil {
		t.Fatal("expected finding-only remediation, got nil")
	}
	if len(steps) == 0 {
		t.Fatal("expected at least 1 step")
	}
	if steps[0].EdgeKind != "CAN_EXECUTE" {
		t.Errorf("EdgeKind = %q, want CAN_EXECUTE", steps[0].EdgeKind)
	}
}

func TestBuildRemediation_EmptyEdges(t *testing.T) {
	path := &AttackPath{
		Nodes: []PathNode{{ID: "n1", Properties: map[string]any{}}},
		Edges: []PathEdge{},
	}
	f := &Finding{
		EdgeKind:   "POISONED_DESCRIPTION",
		SourceID:   "tool-1",
		SourceName: "MalTool",
		TargetID:   "tool-1",
		TargetName: "MalTool",
	}

	steps := BuildRemediation(path, f)
	if steps == nil {
		t.Fatal("expected finding-only remediation, got nil")
	}
	if steps[0].EdgeKind != "POISONED_DESCRIPTION" {
		t.Errorf("EdgeKind = %q, want POISONED_DESCRIPTION", steps[0].EdgeKind)
	}
}

func TestBuildFindingOnlyRemediation(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_EXECUTE",
		SourceID:   "tool-1",
		SourceName: "RunCode",
		TargetID:   "host-1",
		TargetName: "prod-server",
	}

	steps := buildFindingOnlyRemediation(f)
	if len(steps) == 0 {
		t.Fatal("expected at least 1 step")
	}
	if steps[0].Step != 1 {
		t.Errorf("Step = %d, want 1", steps[0].Step)
	}
	if !strings.Contains(steps[0].Description, "RunCode") {
		t.Errorf("Description = %q, expected source name", steps[0].Description)
	}
	if !strings.Contains(steps[0].Description, "prod-server") {
		t.Errorf("Description = %q, expected target name", steps[0].Description)
	}
}

func TestBuildFindingOnlyRemediation_UnknownEdgeKind(t *testing.T) {
	f := &Finding{EdgeKind: "DOES_NOT_EXIST", SourceID: "a", TargetID: "b"}
	steps := buildFindingOnlyRemediation(f)
	if steps != nil {
		t.Errorf("expected nil for unknown edge kind, got %v", steps)
	}
}

func TestBuildFindingOnlyRemediation_EmptyNames(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_EXECUTE",
		SourceID:   "tool-1",
		SourceName: "",
		TargetID:   "host-1",
		TargetName: "",
	}

	steps := buildFindingOnlyRemediation(f)
	if len(steps) == 0 {
		t.Fatal("expected at least 1 step")
	}
	if !strings.Contains(steps[0].Description, "tool-1") {
		t.Errorf("Description = %q, expected SourceID as fallback", steps[0].Description)
	}
	if !strings.Contains(steps[0].Description, "host-1") {
		t.Errorf("Description = %q, expected TargetID as fallback", steps[0].Description)
	}
}

func TestInterpolateDesc(t *testing.T) {
	tests := []struct {
		name     string
		template string
		src      string
		tgt      string
		want     string
	}{
		{
			name:     "zero placeholders",
			template: "No action required",
			src:      "foo",
			tgt:      "bar",
			want:     "No action required",
		},
		{
			name:     "one placeholder",
			template: "Server %s is exposed",
			src:      "foo",
			tgt:      "bar",
			want:     "Server foo is exposed",
		},
		{
			name:     "two placeholders",
			template: "Tool %s accesses %s",
			src:      "foo",
			tgt:      "bar",
			want:     "Tool foo accesses bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := interpolateDesc(tt.template, tt.src, tt.tgt)
			if got != tt.want {
				t.Errorf("interpolateDesc() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildNodeNameMap(t *testing.T) {
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "n1", Properties: map[string]any{"name": "NodeOne"}},
			{ID: "n2", Properties: map[string]any{"name": "NodeTwo"}},
			{ID: "n3", Properties: map[string]any{}},
		},
	}

	m := buildNodeNameMap(path)
	if m["n1"] != "NodeOne" {
		t.Errorf("m[n1] = %q, want NodeOne", m["n1"])
	}
	if m["n2"] != "NodeTwo" {
		t.Errorf("m[n2] = %q, want NodeTwo", m["n2"])
	}
	if m["n3"] != "n3" {
		t.Errorf("m[n3] = %q, want n3 (fallback to ID)", m["n3"])
	}
}

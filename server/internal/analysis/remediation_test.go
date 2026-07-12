package analysis

import (
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/model"
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

	f := &model.Finding{EdgeKind: "CAN_REACH", SourceID: "agent-1", TargetID: "res-1"}
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

	f := &model.Finding{EdgeKind: "CAN_REACH", SourceID: "a1", TargetID: "s2"}
	steps := BuildRemediation(path, f)

	if len(steps) != 2 {
		t.Fatalf("got %d steps, want 2 actor-specific TRUSTS_SERVER steps", len(steps))
	}
	if steps[0].EdgeKind != "TRUSTS_SERVER" {
		t.Errorf("EdgeKind = %q, want TRUSTS_SERVER", steps[0].EdgeKind)
	}
}

func TestBuildRemediation_NilPath(t *testing.T) {
	f := &model.Finding{
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
	f := &model.Finding{
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
	f := &model.Finding{
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
	// AH-UI-11: an unknown edge kind yields an empty (non-nil) slice so the
	// JSON response is `[]` and the client's steps.length read is safe.
	f := &model.Finding{EdgeKind: "DOES_NOT_EXIST", SourceID: "a", TargetID: "b"}
	steps := buildFindingOnlyRemediation(f)
	if steps == nil {
		t.Error("expected non-nil empty slice for unknown edge kind, got nil")
	}
	if len(steps) != 0 {
		t.Errorf("expected 0 steps for unknown edge kind, got %d", len(steps))
	}
}

func TestBuildRemediation_TrustsServerNamesActorsCorrectly(t *testing.T) {
	// AH-UI-24: the TRUSTS_SERVER remediation must name the agent and server in
	// their correct roles and must not assert an unobserved "no authentication"
	// fact.
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "agent-1", Properties: map[string]any{"name": "MyAgent"}},
			{ID: "srv-1", Properties: map[string]any{"name": "ProdServer"}},
		},
		Edges: []PathEdge{{Source: "agent-1", Target: "srv-1", Kind: "TRUSTS_SERVER"}},
	}
	f := &model.Finding{EdgeKind: "TRUSTS_SERVER", SourceID: "agent-1", TargetID: "srv-1"}
	steps := BuildRemediation(path, f)
	if len(steps) == 0 {
		t.Fatal("expected a remediation step")
	}
	d := steps[0].Description
	if !strings.Contains(d, "MyAgent") || !strings.Contains(d, "ProdServer") {
		t.Errorf("description %q should name agent MyAgent and server ProdServer", d)
	}
	// Must not fabricate an absolute claim that there is no authentication.
	if strings.Contains(strings.ToLower(d), "with no authentication") {
		t.Errorf("description %q must not assert unobserved 'no authentication'", d)
	}
}

func TestBuildRemediation_AuthenticationAdviceUsesTargetEvidence(t *testing.T) {
	tests := []struct {
		name         string
		authMethod   any
		authEvidence any
		want         string
		notWant      string
	}{
		{
			name:         "explicit none",
			authMethod:   "none",
			authEvidence: "anonymous_probe_succeeded",
			want:         "explicitly reports no authentication",
		},
		{
			name:       "none without explicit evidence remains unverified",
			authMethod: "none",
			want:       "explicit anonymous-access evidence is unavailable",
			notWant:    "explicitly reports no authentication",
		},
		{
			name:       "explicit oauth",
			authMethod: "oauth",
			want:       "reports oauth authentication",
			notWant:    "no authentication",
		},
		{
			name:    "unknown",
			want:    "Authentication evidence",
			notWant: "no authentication",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			properties := map[string]any{"name": "ProdServer"}
			if tt.authMethod != nil {
				properties["auth_method"] = tt.authMethod
			}
			if tt.authEvidence != nil {
				properties["auth_evidence"] = tt.authEvidence
			}
			path := &AttackPath{
				Nodes: []PathNode{
					{ID: "agent", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "Agent"}},
					{ID: "server", Kinds: []string{"MCPServer"}, Properties: properties},
				},
				Edges: []PathEdge{{Source: "agent", Target: "server", Kind: "TRUSTS_SERVER"}},
			}
			steps := BuildRemediation(path, &model.Finding{EdgeKind: "CAN_REACH"})
			if len(steps) != 1 {
				t.Fatalf("steps = %+v", steps)
			}
			if !strings.Contains(steps[0].Description, tt.want) {
				t.Fatalf("description %q missing %q", steps[0].Description, tt.want)
			}
			if tt.notWant != "" && strings.Contains(steps[0].Description, tt.notWant) {
				t.Fatalf("description %q unexpectedly contains %q", steps[0].Description, tt.notWant)
			}
			if steps[0].Source.Kind != "AgentInstance" ||
				steps[0].Target.Kind != "MCPServer" {
				t.Fatalf("typed actors = %+v -> %+v", steps[0].Source, steps[0].Target)
			}
		})
	}
}

func TestBuildRemediation_RetainsFindingVariantAlongsideWitnessSteps(t *testing.T) {
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "agent", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "Agent"}},
			{ID: "server", Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "Server"}},
			{ID: "credential", Kinds: []string{"Credential"}, Properties: map[string]any{
				"name": "Provider key", "material_status": "observed", "exposure_status": "exposed",
			}},
		},
		Edges: []PathEdge{
			{Source: "agent", Target: "server", Kind: "TRUSTS_SERVER"},
			{Source: "server", Target: "credential", Kind: "HAS_ENV_VAR"},
		},
	}
	finding := &model.Finding{
		EdgeKind:   "CAN_REACH",
		SourceID:   "agent",
		SourceName: "Agent",
		SourceKind: "AgentInstance",
		TargetID:   "credential",
		TargetName: "Provider key",
		TargetKind: "Credential",
		Variant:    model.FindingVariantCredentialObservedMaterial,
	}
	steps := BuildRemediation(path, finding)
	if len(steps) != 3 {
		t.Fatalf("steps = %+v, want variant advice plus two witness steps", steps)
	}
	if steps[0].Title != "Rotate observed credential material" {
		t.Fatalf("first step = %+v, want retained variant remediation", steps[0])
	}
}

func TestBuildRemediation_RetainsExfiltrationChannelsWithPath(t *testing.T) {
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "agent", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "Agent"}},
			{ID: "tool", Kinds: []string{"MCPTool"}, Properties: map[string]any{"name": "Writer"}},
		},
		Edges: []PathEdge{{Source: "agent", Target: "tool", Kind: "PROVIDES_TOOL"}},
	}
	finding := &model.Finding{
		EdgeKind: "CAN_EXFILTRATE_VIA",
		SourceID: "agent", SourceKind: "AgentInstance",
		TargetID: "tool", TargetKind: "MCPTool",
		Evidence: model.FindingEvidence{Channels: []string{"file_write"}},
	}
	steps := BuildRemediation(path, finding)
	if len(steps) != 2 || len(steps[0].Channels) != 1 || steps[0].Channels[0] != "file_write" {
		t.Fatalf("steps = %+v, want retained file_write finding remediation", steps)
	}
}

func TestBuildFindingOnlyRemediation_CredentialVariants(t *testing.T) {
	base := model.Finding{
		EdgeKind:   "CAN_REACH",
		SourceID:   "agent",
		SourceName: "Agent",
		SourceKind: "AgentInstance",
		TargetID:   "credential",
		TargetName: "Provider key",
		TargetKind: "Credential",
	}
	observed := base
	observed.Variant = model.FindingVariantCredentialObservedMaterial
	observedSteps := buildFindingOnlyRemediation(&observed)
	if len(observedSteps) != 1 ||
		!strings.Contains(observedSteps[0].Description, "Revoke or rotate") {
		t.Fatalf("observed remediation = %+v", observedSteps)
	}

	reference := base
	reference.Variant = model.FindingVariantCredentialReference
	referenceSteps := buildFindingOnlyRemediation(&reference)
	if len(referenceSteps) != 1 ||
		strings.Contains(strings.ToLower(referenceSteps[0].Description), "revoke or rotate it") ||
		!strings.Contains(referenceSteps[0].Description, "reference-only") {
		t.Fatalf("reference remediation = %+v", referenceSteps)
	}
}

func TestBuildFindingOnlyRemediation_EmptyNames(t *testing.T) {
	f := &model.Finding{
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
			template: "No generated recommendation",
			src:      "foo",
			tgt:      "bar",
			want:     "No generated recommendation",
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

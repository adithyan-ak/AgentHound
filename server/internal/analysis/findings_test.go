package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestQueryFindings_AllEdgeKinds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "TestAgent", "source_kind": "AgentInstance",
				"target_id": "tool-1", "target_name": "ExfilTool", "target_kind": "MCPTool",
				"edge_kind": "CAN_EXFILTRATE_VIA", "confidence": 0.8,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "agent-1", "source_name": "TestAgent", "source_kind": "AgentInstance",
				"target_id": "res-1", "target_name": "ProdDB", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.9,
				"cross_protocol": false, "target_sensitivity": "critical",
			},
			{
				"source_id": "tool-1", "source_name": "MalTool", "source_kind": "MCPTool",
				"target_id": "tool-1", "target_name": "MalTool", "target_kind": "MCPTool",
				"edge_kind": "POISONED_DESCRIPTION", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "tool-1", "source_name": "ReadDB", "source_kind": "MCPTool",
				"target_id": "tool-2", "target_name": "OrigDB", "target_kind": "MCPTool",
				"edge_kind": "SHADOWS", "confidence": 0.6,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "tool-1", "source_name": "RunCode", "source_kind": "MCPTool",
				"target_id": "host-1", "target_name": "prod-server", "target_kind": "Host",
				"edge_kind": "CAN_EXECUTE", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("QueryFindings() error = %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("got %d findings, want 5", len(findings))
	}

	expected := []struct {
		edgeKind string
		severity string
		category string
	}{
		{"CAN_EXFILTRATE_VIA", "critical", "Data Exfiltration"},
		{"CAN_REACH", "critical", "Transitive Access"},
		{"POISONED_DESCRIPTION", "high", "Prompt Injection"},
		{"SHADOWS", "high", "Tool Shadowing"},
		{"CAN_EXECUTE", "medium", "Remote Execution"},
	}

	for i, exp := range expected {
		f := findings[i]
		if f.EdgeKind != exp.edgeKind {
			t.Errorf("findings[%d].EdgeKind = %q, want %q", i, f.EdgeKind, exp.edgeKind)
		}
		if f.Severity != exp.severity {
			t.Errorf("findings[%d].Severity = %q, want %q", i, f.Severity, exp.severity)
		}
		if f.Category != exp.category {
			t.Errorf("findings[%d].Category = %q, want %q", i, f.Category, exp.category)
		}
		if f.ID == "" {
			t.Errorf("findings[%d].ID is empty", i)
		}
	}
}

// TestQueryFindings_VerifiedUpgradeNoDuplicate asserts a CAN_REACH edge carrying
// reach_evidence_state=verified (set by the CAN_REACH processor's re-correlation
// of a CREDENTIAL_REACH_VERIFIED edge) yields exactly ONE finding whose evidence
// state is upgraded to verified — the same finding, not a duplicate.
func TestQueryFindings_VerifiedUpgradeNoDuplicate(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "TestAgent", "source_kind": "AgentInstance",
				"target_id": "res-1", "target_name": "ProdDB", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "critical",
				"source_collector":                    "mcp",
				"reach_evidence_state":                "verified",
				"verified_scenario_id":                "cred-reach",
				"verified_scenario_version":           1,
				"verified_run_id":                     "run-verified",
				"verified_at":                         "2026-07-13T12:00:00Z",
				"verified_oracle_type":                "differential_credential_reach",
				"verified_outcome":                    "credential_gated_reach_verified",
				"verified_control_stage":              "initialize",
				"verified_control_status":             "denied",
				"verified_control_resource_addressed": false,
				"verified_authed_stage":               "resource_read",
				"verified_authed_status":              "allowed",
				"verified_authed_resource_addressed":  true,
				"verified_cleanup_status":             "not_applicable",
			},
		},
	}
	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("QueryFindings error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("verified upgrade must not duplicate the finding: got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.EdgeKind != "CAN_REACH" {
		t.Fatalf("edge kind = %q, want CAN_REACH", f.EdgeKind)
	}
	if f.Evidence.State != model.FindingEvidenceVerified {
		t.Fatalf("evidence state = %q, want verified", f.Evidence.State)
	}
	verification := f.Evidence.Verification
	if verification == nil ||
		verification.ScenarioID != "cred-reach" ||
		verification.CampaignRunID != "run-verified" ||
		verification.ControlStage != "initialize" ||
		verification.ControlResourceAddressed ||
		verification.AuthedStage != "resource_read" ||
		!verification.AuthedResourceAddressed ||
		verification.CleanupStatus != "not_applicable" {
		t.Fatalf("structured verification metadata = %+v", verification)
	}
	// Verified + critical sensitivity + confidence 1.0 => critical severity.
	if f.Severity != "critical" {
		t.Fatalf("severity = %q, want critical", f.Severity)
	}
}

// TestQueryFindings_UnverifiedCanReachStaysInferred confirms the upgrade does not
// fire for an ordinary CAN_REACH edge with no verification evidence.
func TestQueryFindings_UnverifiedCanReachStaysInferred(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "res-1", "target_name": "DB", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.9,
				"cross_protocol": false, "target_sensitivity": "high",
				"source_collector": "mcp",
			},
		},
	}
	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 || findings[0].Evidence.State == model.FindingEvidenceVerified {
		t.Fatalf("unverified CAN_REACH must not be marked verified: %+v", findings)
	}
}

func TestQueryFindings_SeverityFilter(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "t1", "target_name": "T", "target_kind": "MCPTool",
				"edge_kind": "CAN_EXFILTRATE_VIA", "confidence": 0.8,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "t1", "source_name": "T", "source_kind": "MCPTool",
				"target_id": "h1", "target_name": "H", "target_kind": "Host",
				"edge_kind": "CAN_EXECUTE", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "critical")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only critical)", len(findings))
	}
	if findings[0].EdgeKind != "CAN_EXFILTRATE_VIA" {
		t.Errorf("EdgeKind = %q", findings[0].EdgeKind)
	}
}

func TestQueryFindings_CrossProtocolIsCalibratedHypothesis(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "ext-1", "source_name": "ExtAgent", "source_kind": "A2AAgent",
				"target_id": "res-1", "target_name": "Secrets", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": true, "target_sensitivity": "low",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != "medium" {
		t.Errorf("cross-protocol CAN_REACH severity = %q, want medium", findings[0].Severity)
	}
	if findings[0].Variant != model.FindingVariantCrossProtocolHostCorrelation ||
		findings[0].Evidence.State != model.FindingEvidenceHypothesis {
		t.Fatalf("cross-protocol classification = %+v", findings[0])
	}
	if !strings.Contains(findings[0].Description, "50%-confidence hypothesis") ||
		!strings.Contains(findings[0].Description, "does not prove") {
		t.Fatalf("cross-protocol wording = %q", findings[0].Description)
	}
}

func TestQueryFindings_CanReachHighSensitivity(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "r1", "target_name": "R", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "high",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
}

func TestQueryFindings_CanReachMediumDefault(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "r1", "target_name": "R", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "low",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

func TestQueryFindings_UnknownEdgeKind(t *testing.T) {
	finding := queryUnknownEdgeFinding(t)

	if finding.Severity != "low" {
		t.Errorf("severity = %q, want low", finding.Severity)
	}
	if finding.Category != "Other" {
		t.Errorf("category = %q, want Other", finding.Category)
	}
	if finding.Evidence.State != model.FindingEvidenceUnknown {
		t.Errorf("legacy finding evidence = %q, want unknown", finding.Evidence.State)
	}
	if finding.OWASPMap == nil {
		t.Error("OWASPMap is nil, want empty array")
	}
	if finding.ATLASMap == nil {
		t.Error("ATLASMap is nil, want empty array")
	}
	if finding.Evidence.Channels == nil {
		t.Error("Evidence.Channels is nil, want empty array")
	}
}

func TestQueryFindings_UnknownEdgeKindMarshalsEmptyArrays(t *testing.T) {
	payload, err := json.Marshal(queryUnknownEdgeFinding(t))
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	var wire struct {
		OWASPMap json.RawMessage `json:"owasp_map"`
		ATLASMap json.RawMessage `json:"atlas_map"`
		Evidence struct {
			Channels json.RawMessage `json:"channels"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if got := string(wire.OWASPMap); got != "[]" {
		t.Errorf("owasp_map = %s, want []", got)
	}
	if got := string(wire.ATLASMap); got != "[]" {
		t.Errorf("atlas_map = %s, want []", got)
	}
	if got := string(wire.Evidence.Channels); got != "[]" {
		t.Errorf("evidence.channels = %s, want []", got)
	}
}

func queryUnknownEdgeFinding(t *testing.T) model.Finding {
	t.Helper()
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "Node",
				"target_id": "b1", "target_name": "B", "target_kind": "Node",
				"edge_kind": "CUSTOM_EDGE", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	return findings[0]
}

func TestQueryFindings_EmptyResult(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: nil}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQueryFindings_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: errors.New("db error")}

	_, err := QueryFindings(context.Background(), mock, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestQueryFindings_MissingTargetNameUsesID(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "res-123", "target_name": nil, "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatal("expected 1 finding")
	}
	if findings[0].TargetName != "" {
		t.Errorf("TargetName = %q, want empty", findings[0].TargetName)
	}
}

func TestQueryFindings_OWASPMap(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "t1", "target_name": "T", "target_kind": "MCPTool",
				"edge_kind": "CAN_EXFILTRATE_VIA", "confidence": 0.8,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings[0].OWASPMap) != 3 {
		t.Errorf("OWASPMap len = %d, want 3", len(findings[0].OWASPMap))
	}
}

func TestQueryFindings_ATLASMap(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "tool-1", "source_name": "PoisonedTool", "source_kind": "MCPTool",
				"target_id": "tool-1", "target_name": "PoisonedTool", "target_kind": "MCPTool",
				"edge_kind": "POISONED_DESCRIPTION", "confidence": 1.0,
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	want := []string{"AML.T0051", "AML.T0110"}
	if len(findings) != 1 || !sameStrings(findings[0].ATLASMap, want) {
		t.Fatalf("ATLASMap = %v, want %v", findings[0].ATLASMap, want)
	}
}

func TestQueryFindings_CredentialChainCritical(t *testing.T) {
	// AH-UI-17: credential-chain findings are critical only when the target
	// carries observed usable material, not from target type alone.
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "Agent", "source_kind": "AgentInstance",
				"target_id": "cred-1", "target_name": "OPENAI_API_KEY", "target_kind": "Credential",
				"edge_kind": "CAN_REACH", "confidence": 0.95,
				"cross_protocol": false, "target_sensitivity": "",
				"source_collector":       "cross_service_credential_chain",
				"target_value_hash":      "sha256-of-secret",
				"target_merge_key":       "value_hash",
				"target_material_status": "observed", "target_exposure_status": "exposed",
			},
		},
	}
	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.Category != "Credential Exposure" {
		t.Errorf("category = %q, want Credential Exposure", f.Category)
	}
	if f.Variant != model.FindingVariantCredentialObservedMaterial ||
		f.Evidence.State != model.FindingEvidenceObserved ||
		f.Evidence.MaterialStatus != "observed" ||
		f.Evidence.ExposureStatus != "exposed" {
		t.Fatalf("observed credential evidence = %+v", f)
	}
	if !contains(f.Description, "Agent") || !contains(f.Description, "OPENAI_API_KEY") ||
		!contains(f.Description, "observed usable material") {
		t.Errorf("description %q should name actor, credential, and observed material", f.Description)
	}
}

func TestQueryFindings_CredentialTargetAloneIsNotCritical(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "Agent", "source_kind": "AgentInstance",
				"target_id": "cred-1", "target_name": "KEY", "target_kind": "Credential",
				"edge_kind": "CAN_REACH", "confidence": 0.95,
				"cross_protocol": false, "target_sensitivity": "",
				"target_value":     "sk-secret",
				"via_gateway":      "legacy-gateway",
				"merge_value_hash": "legacy-hash",
			},
		},
	}
	findings, err := QueryFindings(context.Background(), mock, "critical")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("target kind alone returned %d critical findings, want 0", len(findings))
	}

	findings, err = QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != "medium" {
		t.Fatalf("target-kind-only finding = %+v, want one medium finding", findings)
	}
	if findings[0].Variant != model.FindingVariantCredentialNodeReference {
		t.Fatalf("legacy properties without canonical provenance produced variant %q, want %q",
			findings[0].Variant, model.FindingVariantCredentialNodeReference)
	}
	if contains(strings.ToLower(findings[0].Description), "exposed credential") {
		t.Errorf("description %q must not claim exposure from target kind alone", findings[0].Description)
	}
}

func TestQueryFindings_CredentialChainWithoutUsableMaterial(t *testing.T) {
	tests := []struct {
		name string
		row  map[string]any
	}{
		{
			name: "synthetic identity",
			row: map[string]any{
				"target_merge_key":  "identity",
				"target_value_hash": "synthetic-provider-name-hash",
			},
		},
		{
			name: "digest only",
			row: map[string]any{
				"target_merge_key": "value_hash",
				"target_value":     "same-returned-digest", "target_value_hash": "same-returned-digest",
			},
		},
		{
			name: "redacted value",
			row: map[string]any{
				"target_merge_key":  "value_hash",
				"target_value_hash": "hash-without-raw-value",
			},
		},
		{
			name: "legacy value without typed evidence",
			row: map[string]any{
				"target_merge_key":  "value_hash",
				"target_value":      "sk-legacy",
				"target_value_hash": "hash-of-legacy",
			},
		},
		{
			name: "explicit masked provider reference",
			row: map[string]any{
				"target_merge_key":       "identity",
				"target_material_status": "masked",
				"target_exposure_status": "not_observed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := map[string]any{
				"source_id": "agent-1", "source_name": "Agent", "source_kind": "AgentInstance",
				"target_id": "cred-1", "target_name": "UPSTREAM_KEY", "target_kind": "Credential",
				"edge_kind": "CAN_REACH", "confidence": 0.95,
				"source_collector": "cross_service_credential_chain",
			}
			for k, v := range tt.row {
				row[k] = v
			}
			mock := &graph.MockGraphDB{QueryResult: []map[string]any{row}}

			findings, err := QueryFindings(context.Background(), mock, "")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.Severity != "medium" || f.Category != "Credential Reachability" {
				t.Errorf("finding = (%s, %s), want medium Credential Reachability", f.Severity, f.Category)
			}
			if f.Variant != model.FindingVariantCredentialReference ||
				f.Evidence.State != model.FindingEvidenceReferenceOnly {
				t.Errorf("reference classification = %+v", f)
			}
			if !contains(f.Description, "no observed usable credential material") {
				t.Errorf("description %q must disclose missing usable material", f.Description)
			}
		})
	}
}

func TestQueryFindings_DescriptionNamesActor(t *testing.T) {
	// AH-UI-31: descriptions must name actors and targets in their actual roles,
	// and exfiltration must report the capability that matched the detector.
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "tool-shadow", "source_name": "ShadowTool", "source_kind": "MCPTool",
				"target_id": "tool-victim", "target_name": "VictimTool", "target_kind": "MCPTool",
				"edge_kind": "SHADOWS", "confidence": 0.9,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "tool-exec", "source_name": "ExecTool", "source_kind": "MCPTool",
				"target_id": "host-1", "target_name": "prod-host", "target_kind": "Host",
				"edge_kind": "CAN_EXECUTE", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "tool-access", "source_name": "ReadTool", "source_kind": "MCPTool",
				"target_id": "res-1", "target_name": "CustomerDB", "target_kind": "MCPResource",
				"edge_kind": "HAS_ACCESS_TO", "confidence": 0.8,
			},
			{
				"source_id": "agent-exfil", "source_name": "OpsAgent", "source_kind": "AgentInstance",
				"target_id": "tool-file", "target_name": "ArchiveWriter", "target_kind": "MCPTool",
				"edge_kind": "CAN_EXFILTRATE_VIA", "confidence": 0.8,
				"target_capabilities": []any{"file_write"},
			},
		},
	}
	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	byKind := map[string]model.Finding{}
	for _, f := range findings {
		byKind[f.EdgeKind] = f
	}
	if d := byKind["SHADOWS"].Description; !contains(d, "ShadowTool") || !contains(d, "VictimTool") {
		t.Errorf("SHADOWS description %q should name source ShadowTool and target VictimTool", d)
	}
	if d := byKind["CAN_EXECUTE"].Description; !contains(d, "ExecTool") || !contains(d, "prod-host") {
		t.Errorf("CAN_EXECUTE description %q should name source ExecTool and host prod-host", d)
	}
	if d := byKind["HAS_ACCESS_TO"].Description; !contains(d, "ReadTool") || !contains(d, "CustomerDB") {
		t.Errorf("HAS_ACCESS_TO description %q should name tool ReadTool and resource CustomerDB", d)
	}
	if d := byKind["CAN_EXFILTRATE_VIA"].Description; !contains(d, "OpsAgent") ||
		!contains(d, "ArchiveWriter") || !contains(d, "file_write") ||
		contains(strings.ToLower(d), "network") {
		t.Errorf("CAN_EXFILTRATE_VIA description %q should name actors and exact file_write channel", d)
	}
	if got := byKind["CAN_EXFILTRATE_VIA"].Evidence.Channels; !sameStrings(got, []string{"file_write"}) {
		t.Errorf("persistable channel evidence = %v, want [file_write]", got)
	}
}

func TestQueryFindings_CapturesExactDetectorWitness(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{{
		"source_id": "agent", "source_name": "Agent", "source_kind": "AgentInstance",
		"target_id": "credential", "target_name": "Provider key", "target_kind": "Credential",
		"edge_kind": "CAN_REACH", "confidence": 0.95,
		"source_collector": "cross_service_credential_chain",
		"target_merge_key": "identity",
		"evidence_version": int64(1),
		"exact_evidence_nodes": []any{
			map[string]any{"id": "agent", "kinds": []any{"AgentInstance"}, "properties": map[string]any{"name": "Agent"}},
			map[string]any{"id": "left", "kinds": []any{"Credential"}, "properties": map[string]any{"name": "Left"}},
			map[string]any{"id": "right", "kinds": []any{"Credential"}, "properties": map[string]any{"name": "Right"}},
			map[string]any{"id": "credential", "kinds": []any{"Credential"}, "properties": map[string]any{"name": "Provider key"}},
		},
		"exact_evidence_edges": []any{
			map[string]any{
				"source": "agent", "target": "left", "kind": "HAS_ENV_VAR",
				"properties": map[string]any{"risk_weight": 0.1},
			},
			map[string]any{
				"source": "right", "target": "credential", "kind": "EXPOSES_CREDENTIAL",
				"properties": map[string]any{"risk_weight": 0.2},
			},
		},
		"exact_evidence_synthetic_edge": []any{
			"left", "right", "VALUE_HASH_MATCH",
			"identity_correlation", "value_hash", "cross_service_credential_chain",
		},
	}}}
	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("QueryFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].ExactEvidence == nil {
		t.Fatalf("exact evidence missing: %+v", findings)
	}
	exact := findings[0].ExactEvidence
	if !exact.Complete || len(exact.Nodes) != 4 || len(exact.Edges) != 3 {
		t.Fatalf("exact evidence = %+v", exact)
	}
	synthetic := exact.Edges[2]
	if !synthetic.Synthetic ||
		synthetic.Kind != "VALUE_HASH_MATCH" ||
		synthetic.Provenance["basis"] != "value_hash" {
		t.Fatalf("synthetic evidence = %+v", synthetic)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func sameStrings(got, want []string) bool {
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

func TestClassifySeverity(t *testing.T) {
	tests := []struct {
		name              string
		edgeKind          string
		crossProtocol     bool
		confidence        float64
		targetSensitivity string
		want              string
	}{
		{"exfiltrate always critical", "CAN_EXFILTRATE_VIA", false, 0.5, "", "critical"},
		{"reach cross-protocol", "CAN_REACH", true, 0.5, "low", "medium"},
		{"reach cross-protocol sensitive target", "CAN_REACH", true, 0.5, "critical", "high"},
		{"reach high-confidence critical resource", "CAN_REACH", false, 0.9, "critical", "critical"},
		{"reach high resource", "CAN_REACH", false, 0.5, "high", "high"},
		{"reach default medium", "CAN_REACH", false, 0.5, "low", "medium"},
		{"poisoned desc high", "POISONED_DESCRIPTION", false, 1.0, "", "high"},
		{"shadows high", "SHADOWS", false, 0.6, "", "high"},
		{"poisoned instr high", "POISONED_INSTRUCTIONS", false, 1.0, "", "high"},
		{"impersonate medium", "CAN_IMPERSONATE", false, 0.8, "", "medium"},
		{"execute medium", "CAN_EXECUTE", false, 1.0, "", "medium"},
		{"has_access_to medium", "HAS_ACCESS_TO", false, 0.7, "", "medium"},
		{"unknown low", "CUSTOM", false, 0.5, "", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySeverity(tt.edgeKind, tt.crossProtocol, tt.confidence, tt.targetSensitivity)
			if got != tt.want {
				t.Errorf("classifySeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

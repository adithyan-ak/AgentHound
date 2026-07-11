package ingest

import (
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func validIngestData() *ingest.IngestData {
	return &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        "mcp",
			CollectorVersion: "0.1.0",
			Timestamp:        "2026-04-06T10:30:00Z",
			ScanID:           "scan-001",
		},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "sha256:aaa", Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "srv"}},
				{ID: "sha256:bbb", Kinds: []string{"MCPTool"}, Properties: map[string]any{"name": "tool"}},
			},
			Edges: []ingest.Edge{
				{Source: "sha256:aaa", Target: "sha256:bbb", Kind: "PROVIDES_TOOL", Properties: map[string]any{}},
			},
		},
	}
}

func TestValidatorAcceptsValid(t *testing.T) {
	v := NewValidator()
	if err := v.Validate(validIngestData()); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidatorAcceptsDeclaredObservationDomains(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Collection = &ingest.CollectionReport{
		State:        ingest.OutcomeComplete,
		CoverageKeys: []string{"mcp"},
	}
	data.Graph.Nodes[0].ObservationDomains = []string{"mcp"}
	data.Graph.Edges[0].ObservationDomains = []string{"mcp"}
	if err := v.Validate(data); err != nil {
		t.Fatalf("declared observation domain rejected: %v", err)
	}
}

func TestValidatorRejectsUndeclaredObservationDomain(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Collection = &ingest.CollectionReport{
		State:        ingest.OutcomeComplete,
		CoverageKeys: []string{"config"},
	}
	data.Graph.Nodes[0].ObservationDomains = []string{"mcp"}

	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].observation_domains[0]")
}

func TestValidatorRejectsBadVersion(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Version = 99
	err := v.Validate(data)
	assertValidationError(t, err, "meta.version")
}

func TestValidatorRejectsBadType(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Type = "wrong"
	err := v.Validate(data)
	assertValidationError(t, err, "meta.type")
}

func TestValidatorRejectsBadCollector(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Collector = "unknown"
	err := v.Validate(data)
	assertValidationError(t, err, "meta.collector")
}

func TestValidatorRejectsEmptyScanID(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.ScanID = ""
	err := v.Validate(data)
	assertValidationError(t, err, "meta.scan_id")
}

func TestValidatorRejectsEmptyNodeID(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].ID = ""
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].id")
}

func TestValidatorRejectsEmptyNodeKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = nil
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].kinds")
}

func TestValidatorRejectsInvalidNodeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = []string{"FakeNode"}
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].kinds[0]")
}

func TestValidatorRejectsCredentialWithoutValueHash(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:         "sha256:cred",
		Kinds:      []string{"Credential"},
		Properties: map[string]any{"name": "API_KEY"},
	})
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[2].properties.value_hash")
}

func TestValidatorAcceptsCredentialWithValueHash(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:         "sha256:cred",
		Kinds:      []string{"Credential"},
		Properties: map[string]any{"name": "API_KEY", "value_hash": "sha256:abc"},
	})
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected credential with value_hash to validate, got: %v", err)
	}
}

func TestValidatorRejectsEmptyEdgeSource(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Source = ""
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source")
}

func TestValidatorRejectsInvalidEdgeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Kind = "FAKE_EDGE"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].kind")
}

func TestValidatorRejectsCompositeEdgeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Kind = "CAN_REACH"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].kind")
}

func TestValidatorRejectsInvalidEdgeSourceKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer) WITH edge MATCH (z) DETACH DELETE z //"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsInvalidEdgeTargetKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].TargetKind = "MCPTool {x:1}) DETACH DELETE n //"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target_kind")
}

func TestValidatorAcceptsValidExplicitEdgeKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer"
	data.Graph.Edges[0].TargetKind = "MCPTool"
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected explicit valid edge kinds to validate, got: %v", err)
	}
}

func TestValidatorRejectsIncompatibleSourceKind(t *testing.T) {
	// MCPTool is a valid node label but not a valid *source* for PROVIDES_TOOL
	// (which must be MCPServer -> MCPTool). AH-UI-30: reject the inverted role.
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPTool"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsIncompatibleTargetKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].TargetKind = "MCPServer"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target_kind")
}

func TestValidatorAcceptsCompatibleEndpointKinds(t *testing.T) {
	// PROVIDES_RESOURCE permits multiple valid sources; JupyterServer is one.
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes,
		ingest.Node{ID: "sha256:jup", Kinds: []string{"JupyterServer"}, Properties: map[string]any{"name": "j"}},
		ingest.Node{ID: "sha256:res", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "r"}},
	)
	data.Graph.Edges = append(data.Graph.Edges, ingest.Edge{
		Source: "sha256:jup", Target: "sha256:res", Kind: "PROVIDES_RESOURCE",
		SourceKind: "JupyterServer", TargetKind: "MCPResource", Properties: map[string]any{},
	})
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected compatible endpoint kinds to validate, got: %v", err)
	}
}

func TestValidatorAcceptsOmittedAlternateEndpointKindsFromActualNodes(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{ID: "sha256:jup", Kinds: []string{"JupyterServer", "AIService"}, Properties: map[string]any{"name": "j"}},
		{ID: "sha256:res", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "r"}},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source: "sha256:jup", Target: "sha256:res", Kind: "PROVIDES_RESOURCE",
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected omitted kinds to resolve from actual nodes, got: %v", err)
	}
}

func TestValidatorAcceptsConcreteExposesEndpointKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{ID: "sha256:webui", Kinds: []string{"OpenWebUIInstance", "AIService"}, Properties: map[string]any{"name": "webui"}},
		{ID: "sha256:ollama", Kinds: []string{"OllamaInstance", "AIService"}, Properties: map[string]any{"name": "ollama"}},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source:     "sha256:webui",
		Target:     "sha256:ollama",
		Kind:       "EXPOSES",
		SourceKind: "OpenWebUIInstance",
		TargetKind: "OllamaInstance",
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected producer's concrete EXPOSES labels to validate, got: %v", err)
	}
}

func TestValidatorRejectsDeclaredKindThatDoesNotMatchReferencedNode(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer"
	data.Graph.Edges[0].TargetKind = "MCPTool"
	// Both declared kinds are valid for PROVIDES_TOOL, but the referenced
	// source node does not actually carry the declared MCPServer label.
	data.Graph.Nodes[0].Kinds = []string{"MCPTool"}

	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsMissingReferencedNode(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Target = "sha256:not-in-artifact"

	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target")
}

func TestValidatorAcceptsReferencedUmbrellaLabel(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{
			ID:         "sha256:gateway",
			Kinds:      []string{"LiteLLMGateway", "AIService"},
			Properties: map[string]any{"name": "gateway"},
		},
		{
			ID:         "sha256:credential",
			Kinds:      []string{"Credential"},
			Properties: map[string]any{"name": "key", "value_hash": "abc"},
		},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source: "sha256:gateway", Target: "sha256:credential",
		Kind: "EXPOSES_CREDENTIAL", SourceKind: "AIService", TargetKind: "Credential",
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected actual AIService umbrella label to validate, got: %v", err)
	}
}

func TestValidatorCollectsAllErrors(t *testing.T) {
	v := NewValidator()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:   99,
			Type:      "wrong",
			Collector: "bad",
			ScanID:    "",
		},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{{ID: "", Kinds: nil}},
			Edges: []ingest.Edge{{Source: "", Target: "", Kind: "FAKE"}},
		},
	}
	err := v.Validate(data)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	if len(ve.Errors) < 7 {
		t.Errorf("expected at least 7 errors, got %d: %+v", len(ve.Errors), ve.Errors)
	}
}

func TestValidatorAcceptsEmptyGraph(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = nil
	data.Graph.Edges = nil
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected no error for empty graph, got: %v", err)
	}
}

func TestValidationError_Error(t *testing.T) {
	ve := &ValidationError{
		Errors: []FieldError{
			{Path: "meta.version", Message: "must be 1"},
			{Path: "meta.type", Message: "must be 'agenthound-ingest'"},
			{Path: "meta.scan_id", Message: "must not be empty"},
		},
	}
	got := ve.Error()
	if got != "validation failed: 3 errors" {
		t.Errorf("Error() = %q, want %q", got, "validation failed: 3 errors")
	}
}

func assertValidationError(t *testing.T, err error, expectedPath string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	for _, fe := range ve.Errors {
		if fe.Path == expectedPath {
			return
		}
	}
	t.Errorf("expected error at path %q, got errors: %+v", expectedPath, ve.Errors)
}

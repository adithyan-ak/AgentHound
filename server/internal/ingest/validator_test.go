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

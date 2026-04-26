package ingest

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestCamelToSnake(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"capabilitySurface", "capability_surface"},
		{"hasInjectionPatterns", "has_injection_patterns"},
		{"scanID", "scan_id"},
		{"descriptionHash", "description_hash"},
		{"already_snake", "already_snake"},
		{"inputSchema", "input_schema"},
		{"HTTPServer", "http_server"},
		{"HTTPSEnabled", "https_enabled"},
		{"name", "name"},
		{"ID", "id"},
		{"", ""},
		{"a", "a"},
		{"A", "a"},
		{"isHTTPS", "is_https"},
		{"collectorVersion", "collector_version"},
	}

	for _, tt := range tests {
		got := CamelToSnake(tt.input)
		if got != tt.expected {
			t.Errorf("CamelToSnake(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNormalizerSetsObjectID(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{ScanID: "scan-1"},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "sha256:abc", Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "srv"}},
			},
		},
	}
	n.Normalize(data)

	if data.Graph.Nodes[0].Properties["objectid"] != "sha256:abc" {
		t.Errorf("objectid not set: %v", data.Graph.Nodes[0].Properties)
	}
}

func TestNormalizerStripsNil(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{ScanID: "scan-1"},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "sha256:abc", Kinds: []string{"MCPServer"}, Properties: map[string]any{
					"name":  "srv",
					"empty": nil,
				}},
			},
		},
	}
	n.Normalize(data)

	if _, exists := data.Graph.Nodes[0].Properties["empty"]; exists {
		t.Error("nil value not stripped")
	}
}

func TestNormalizerConvertsKeysToSnakeCase(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{ScanID: "scan-1"},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "sha256:abc", Kinds: []string{"MCPServer"}, Properties: map[string]any{
					"capabilitySurface": []any{"shell_access"},
				}},
			},
		},
	}
	n.Normalize(data)

	props := data.Graph.Nodes[0].Properties
	if _, ok := props["capability_surface"]; !ok {
		t.Errorf("expected snake_case key, got: %v", props)
	}
	if _, ok := props["capabilitySurface"]; ok {
		t.Error("camelCase key should have been converted")
	}
}

func TestNormalizerSerializesComplexValues(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{ScanID: "scan-1"},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "sha256:abc", Kinds: []string{"MCPTool"}, Properties: map[string]any{
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"query": map[string]any{"type": "string"},
						},
					},
				}},
			},
		},
	}
	warnings := n.Normalize(data)

	val := data.Graph.Nodes[0].Properties["input_schema"]
	if _, ok := val.(string); !ok {
		t.Errorf("expected JSON string, got %T: %v", val, val)
	}
	if len(warnings) == 0 {
		t.Error("expected serialization warning")
	}
}

func TestNormalizerInitializesNilProperties(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{ScanID: "scan-1"},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "sha256:abc", Kinds: []string{"MCPServer"}, Properties: nil},
			},
		},
	}
	n.Normalize(data)

	if data.Graph.Nodes[0].Properties == nil {
		t.Error("nil properties not initialized")
	}
}

func TestNormalizerEdgeProperties(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{ScanID: "scan-1"},
		Graph: ingest.GraphData{
			Edges: []ingest.Edge{
				{Source: "a", Target: "b", Kind: "PROVIDES_TOOL", Properties: nil},
			},
		},
	}
	n.Normalize(data)

	if data.Graph.Edges[0].Properties == nil {
		t.Error("nil edge properties not initialized")
	}
}

func TestIsHomogeneous_AllBool(t *testing.T) {
	if !isHomogeneous([]any{true, false, true}) {
		t.Error("expected homogeneous for all-bool slice")
	}
}

func TestIsHomogeneous_AllFloat64(t *testing.T) {
	if !isHomogeneous([]any{1.0, 2.0}) {
		t.Error("expected homogeneous for all-float64 slice")
	}
}

func TestIsHomogeneous_AllString(t *testing.T) {
	if !isHomogeneous([]any{"a", "b"}) {
		t.Error("expected homogeneous for all-string slice")
	}
}

func TestIsHomogeneous_AllInt64(t *testing.T) {
	if !isHomogeneous([]any{int64(1), int64(2)}) {
		t.Error("expected homogeneous for all-int64 slice")
	}
}

func TestIsHomogeneous_Mixed(t *testing.T) {
	if isHomogeneous([]any{"a", 1.0}) {
		t.Error("expected non-homogeneous for mixed-type slice")
	}
}

func TestIsHomogeneous_Empty(t *testing.T) {
	if !isHomogeneous([]any{}) {
		t.Error("expected homogeneous for empty slice")
	}
}

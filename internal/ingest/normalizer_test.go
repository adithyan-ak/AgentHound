package ingest

import (
	"testing"

	"github.com/adithyan-ak/agenthound/internal/model"
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
	data := &model.IngestData{
		Meta: model.IngestMeta{ScanID: "scan-1"},
		Graph: model.GraphData{
			Nodes: []model.Node{
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
	data := &model.IngestData{
		Meta: model.IngestMeta{ScanID: "scan-1"},
		Graph: model.GraphData{
			Nodes: []model.Node{
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
	data := &model.IngestData{
		Meta: model.IngestMeta{ScanID: "scan-1"},
		Graph: model.GraphData{
			Nodes: []model.Node{
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
	data := &model.IngestData{
		Meta: model.IngestMeta{ScanID: "scan-1"},
		Graph: model.GraphData{
			Nodes: []model.Node{
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
	data := &model.IngestData{
		Meta: model.IngestMeta{ScanID: "scan-1"},
		Graph: model.GraphData{
			Nodes: []model.Node{
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
	data := &model.IngestData{
		Meta: model.IngestMeta{ScanID: "scan-1"},
		Graph: model.GraphData{
			Edges: []model.Edge{
				{Source: "a", Target: "b", Kind: "PROVIDES_TOOL", Properties: nil},
			},
		},
	}
	n.Normalize(data)

	if data.Graph.Edges[0].Properties == nil {
		t.Error("nil edge properties not initialized")
	}
}

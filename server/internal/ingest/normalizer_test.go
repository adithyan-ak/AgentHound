package ingest

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
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

func TestNormalizerMarksLegacyStdioIdentityUnresolved(t *testing.T) {
	data := &ingest.IngestData{
		Graph: ingest.GraphData{Nodes: []ingest.Node{{
			ID:    "legacy-v1",
			Kinds: []string{"MCPServer"},
			Properties: map[string]any{
				"transport": "stdio",
			},
		}}},
	}
	NewNormalizer().Normalize(data)
	props := data.Graph.Nodes[0].Properties
	if props["id_scheme"] != ingest.MCPStdioIdentitySchemeV1 ||
		props["identity_compatibility"] != string(ingest.IdentityAliasUnresolved) {
		t.Fatalf("legacy stdio compatibility = %+v", props)
	}
}

func TestNormalizerSeparatesLegacyLocalProcessFromAnonymousAuth(t *testing.T) {
	data := &ingest.IngestData{
		Graph: ingest.GraphData{Nodes: []ingest.Node{{
			ID:    "legacy-local",
			Kinds: []string{"MCPServer"},
			Properties: map[string]any{
				"transport":      "stdio",
				"auth_method":    "none",
				"auth_assurance": "unauthenticated",
				"auth_evidence":  common.AuthEvidenceLocalProcess,
			},
		}}},
	}

	NewNormalizer().Normalize(data)
	props := data.Graph.Nodes[0].Properties
	if props["auth_method"] != string(common.AuthUnknown) ||
		props["auth_assurance"] != string(common.AuthAssuranceUnknown) {
		t.Fatalf("legacy local-process auth was not normalized: %+v", props)
	}
}

func TestNormalizerQuarantinesAmbiguousLegacyAggregate(t *testing.T) {
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{IdentityAliases: []ingest.IdentityAlias{{
			LegacyID:   "legacy-v1",
			CurrentIDs: []string{"current-a", "current-b"},
			State:      ingest.IdentityAliasAmbiguous,
		}}},
		Graph: ingest.GraphData{Nodes: []ingest.Node{{
			ID:    "legacy-v1",
			Kinds: []string{"MCPServer"},
			Properties: map[string]any{
				"transport": "stdio",
			},
		}}},
	}
	NewNormalizer().Normalize(data)
	props := data.Graph.Nodes[0].Properties
	if props["identity_compatibility"] != string(ingest.IdentityAliasAmbiguous) ||
		props["identity_quarantined"] != true {
		t.Fatalf("ambiguous legacy identity was not quarantined: %+v", props)
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
	if warnings[0].Code != "complex_property_serialized" ||
		warnings[0].Status != ingest.NormalizationStatusWarning ||
		warnings[0].PublicationUnsafe {
		t.Fatalf("serialization warning classification = %+v", warnings[0])
	}
}

func TestNormalizerClassifiesDroppedPropertyAsPublicationUnsafe(t *testing.T) {
	data := &ingest.IngestData{
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{{
				ID:    "node",
				Kinds: []string{"MCPServer"},
				Properties: map[string]any{
					"unsupported": map[string]any{"channel": make(chan int)},
				},
			}},
		},
	}

	warnings := NewNormalizer().Normalize(data)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want one", warnings)
	}
	warning := warnings[0]
	if warning.Code != "property_dropped" ||
		warning.Status != ingest.NormalizationStatusDegraded ||
		!warning.PublicationUnsafe {
		t.Fatalf("dropped-property warning = %+v", warning)
	}
	if _, exists := data.Graph.Nodes[0].Properties["unsupported"]; exists {
		t.Fatal("unsupported property was not dropped")
	}
}

func TestNormalizerWarningsAreDeterministic(t *testing.T) {
	makeData := func() *ingest.IngestData {
		return &ingest.IngestData{
			Graph: ingest.GraphData{Nodes: []ingest.Node{{
				ID:    "node",
				Kinds: []string{"MCPServer"},
				Properties: map[string]any{
					"zNested": map[string]any{"z": true},
					"aNested": map[string]any{"a": true},
				},
			}}},
		}
	}

	first := NewNormalizer().Normalize(makeData())
	second := NewNormalizer().Normalize(makeData())
	if len(first) != 2 || len(second) != 2 ||
		first[0].Property != "a_nested" ||
		first[1].Property != "z_nested" ||
		first[0].Message != second[0].Message ||
		first[1].Message != second[1].Message {
		t.Fatalf("warning order is not deterministic: first=%+v second=%+v", first, second)
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

func TestNormalizerDerivesEndpointKindsFromReferencedNodes(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "jupyter", Kinds: []string{"JupyterServer", "AIService"}},
				{ID: "resource", Kinds: []string{"MCPResource"}},
			},
			Edges: []ingest.Edge{{
				Source: "jupyter",
				Target: "resource",
				Kind:   "PROVIDES_RESOURCE",
			}},
		},
	}

	n.Normalize(data)

	edge := data.Graph.Edges[0]
	if edge.SourceKind != "JupyterServer" || edge.TargetKind != "MCPResource" {
		t.Fatalf("endpoint kinds = %q -> %q, want JupyterServer -> MCPResource", edge.SourceKind, edge.TargetKind)
	}
}

func TestNormalizerDerivesEndpointKindsFromMergedDuplicateNodes(t *testing.T) {
	data := &ingest.IngestData{
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "service", Kinds: []string{"JupyterServer"}},
				{ID: "service", Kinds: []string{"AIService"}},
				{ID: "resource", Kinds: []string{"MCPResource"}},
			},
			Edges: []ingest.Edge{{
				Source: "service",
				Target: "resource",
				Kind:   "PROVIDES_RESOURCE",
			}},
		},
	}

	NewNormalizer().Normalize(data)

	edge := data.Graph.Edges[0]
	if edge.SourceKind != "JupyterServer" || edge.TargetKind != "MCPResource" {
		t.Fatalf("endpoint kinds = %q -> %q, want JupyterServer -> MCPResource", edge.SourceKind, edge.TargetKind)
	}
}

func TestNormalizerPreservesExplicitUmbrellaEndpointKind(t *testing.T) {
	n := NewNormalizer()
	data := &ingest.IngestData{
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{ID: "gateway", Kinds: []string{"LiteLLMGateway", "AIService"}},
				{ID: "credential", Kinds: []string{"Credential"}},
			},
			Edges: []ingest.Edge{{
				Source:     "gateway",
				Target:     "credential",
				Kind:       "EXPOSES_CREDENTIAL",
				SourceKind: "AIService",
			}},
		},
	}

	n.Normalize(data)

	edge := data.Graph.Edges[0]
	if edge.SourceKind != "AIService" || edge.TargetKind != "Credential" {
		t.Fatalf("endpoint kinds = %q -> %q, want AIService -> Credential", edge.SourceKind, edge.TargetKind)
	}
}

func TestNormalizerInitializesNilGraphCollections(t *testing.T) {
	data := &ingest.IngestData{}
	NewNormalizer().Normalize(data)
	if data.Graph.Nodes == nil || data.Graph.Edges == nil {
		t.Fatal("normalizer must materialize nil graph collections as empty slices")
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

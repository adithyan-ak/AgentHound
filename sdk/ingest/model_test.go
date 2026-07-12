package ingest

import (
	"encoding/json"
	"testing"
)

func TestNodeJSONRoundTrip(t *testing.T) {
	n := Node{
		ID:    "sha256:abc123",
		Kinds: []string{"MCPServer"},
		Properties: map[string]any{
			"name":      "test-server",
			"transport": "stdio",
		},
	}

	data, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Node
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != n.ID {
		t.Errorf("ID: got %q, want %q", got.ID, n.ID)
	}
	if len(got.Kinds) != 1 || got.Kinds[0] != "MCPServer" {
		t.Errorf("Kinds: got %v, want [MCPServer]", got.Kinds)
	}
	if got.Properties["name"] != "test-server" {
		t.Errorf("Properties[name]: got %v, want test-server", got.Properties["name"])
	}
}

func TestEdgeJSONRoundTrip(t *testing.T) {
	e := Edge{
		Source: "sha256:aaa",
		Target: "sha256:bbb",
		Kind:   "PROVIDES_TOOL",
		Properties: map[string]any{
			"confidence": 1.0,
		},
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Edge
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Source != e.Source || got.Target != e.Target || got.Kind != e.Kind {
		t.Errorf("edge mismatch: got %+v, want %+v", got, e)
	}
}

func TestIngestDataJSONRoundTrip(t *testing.T) {
	input := `{
		"meta": {
			"version": 1,
			"type": "agenthound-ingest",
			"collector": "mcp",
			"collector_version": "0.1.0",
			"timestamp": "2026-04-06T10:30:00Z",
			"scan_id": "scan-001"
		},
		"graph": {
			"nodes": [{"id": "sha256:aaa", "kinds": ["MCPServer"], "properties": {"name": "srv"}}],
			"edges": [{"source": "sha256:aaa", "target": "sha256:bbb", "kind": "PROVIDES_TOOL", "properties": {}}]
		}
	}`

	var d IngestData
	if err := json.Unmarshal([]byte(input), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if d.Meta.Version != 1 {
		t.Errorf("meta.version: got %d, want 1", d.Meta.Version)
	}
	if d.Meta.Collector != "mcp" {
		t.Errorf("meta.collector: got %q, want mcp", d.Meta.Collector)
	}
	if len(d.Graph.Nodes) != 1 {
		t.Errorf("nodes count: got %d, want 1", len(d.Graph.Nodes))
	}
	if len(d.Graph.Edges) != 1 {
		t.Errorf("edges count: got %d, want 1", len(d.Graph.Edges))
	}
}

func TestAllowedNodeKindsComplete(t *testing.T) {
	if len(AllowedNodeKinds) != 23 {
		t.Errorf("AllowedNodeKinds: got %d entries, want 23", len(AllowedNodeKinds))
	}
}

func TestAllNodeLabelsComplete(t *testing.T) {
	// All 23 labels are collector-produced; the unproduced synthetic
	// ResourceGroup/TrustZone kinds were removed in the cleanup phase, so
	// AllNodeLabels now matches AllowedNodeKinds exactly.
	if len(AllNodeLabels) != 23 {
		t.Errorf("AllNodeLabels: got %d entries, want 23", len(AllNodeLabels))
	}
	for _, label := range AllNodeLabels {
		if !AllowedNodeKinds[label] {
			t.Errorf("AllNodeLabels contains non-collector-produced label %q", label)
		}
	}
}

func TestAllowedEdgeKindsComplete(t *testing.T) {
	if len(AllowedEdgeKinds) != 32 {
		t.Errorf("AllowedEdgeKinds: got %d entries, want 32", len(AllowedEdgeKinds))
	}
}

func TestRawEdgeKindsSubsetOfAllowed(t *testing.T) {
	for kind := range RawEdgeKinds {
		if !AllowedEdgeKinds[kind] {
			t.Errorf("RawEdgeKind %q not in AllowedEdgeKinds", kind)
		}
	}
}

// TestAIServiceKindsRegistered guards against accidental removal of the v0.2
// AI-service node kinds + edge kinds. The credential-chain demo and every
// downstream consumer (writer, schema, post-processors, UI) depends on these
// being present in their respective maps.
func TestAIServiceKindsRegistered(t *testing.T) {
	wantNodeKinds := []string{
		"OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
		"LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance",
		"AIService",
	}
	for _, k := range wantNodeKinds {
		if !AllowedNodeKinds[k] {
			t.Errorf("AllowedNodeKinds missing v0.2 kind %q", k)
		}
	}

	// AllNodeLabels is a slice; convert to a set for membership tests.
	labelSet := make(map[string]bool, len(AllNodeLabels))
	for _, l := range AllNodeLabels {
		labelSet[l] = true
	}
	for _, k := range wantNodeKinds {
		if !labelSet[k] {
			t.Errorf("AllNodeLabels missing v0.2 label %q", k)
		}
	}

	wantEdgeKinds := []string{"EXPOSES", "EXPOSES_CREDENTIAL"}
	for _, k := range wantEdgeKinds {
		if !RawEdgeKinds[k] {
			t.Errorf("RawEdgeKinds missing v0.2 edge %q (validator gate at server/internal/ingest/validator.go:80 will reject ingest)", k)
		}
		if !AllowedEdgeKinds[k] {
			t.Errorf("AllowedEdgeKinds missing v0.2 edge %q", k)
		}
	}

	// AIService must be in UmbrellaLabels — the schema-init loop relies on
	// this to skip the umbrella when creating uniqueness constraints.
	if !UmbrellaLabels["AIService"] {
		t.Error("UmbrellaLabels missing AIService — schema-init will create a duplicate constraint that breaks multi-label MERGE")
	}
}

// TestAIModelKindRegistered guards the v0.3 AIModel + PROVIDES_MODEL additions.
// The Ollama Looter (modules/ollamaloot) emits one :AIModel per model surfaced
// via /api/tags + /api/show, joined by an OllamaInstance -[PROVIDES_MODEL]->
// AIModel edge. AIModel is NOT an umbrella — it's a per-kind label that gets
// its own uniqueness constraint via the AllNodeLabels loop.
func TestAIModelKindRegistered(t *testing.T) {
	if !AllowedNodeKinds["AIModel"] {
		t.Error("AllowedNodeKinds missing v0.3 kind \"AIModel\"")
	}
	labelSet := make(map[string]bool, len(AllNodeLabels))
	for _, l := range AllNodeLabels {
		labelSet[l] = true
	}
	if !labelSet["AIModel"] {
		t.Error("AllNodeLabels missing v0.3 label \"AIModel\"")
	}
	if UmbrellaLabels["AIModel"] {
		t.Error("AIModel must NOT be in UmbrellaLabels — it gets its own uniqueness constraint")
	}
	if !RawEdgeKinds["PROVIDES_MODEL"] {
		t.Error("RawEdgeKinds missing v0.3 edge \"PROVIDES_MODEL\"")
	}
	if !AllowedEdgeKinds["PROVIDES_MODEL"] {
		t.Error("AllowedEdgeKinds missing v0.3 edge \"PROVIDES_MODEL\"")
	}
	ep, ok := EdgeKindEndpoints["PROVIDES_MODEL"]
	if !ok {
		t.Fatal("EdgeKindEndpoints missing PROVIDES_MODEL")
	}
	if len(ep.SourceKinds) == 0 || ep.SourceKinds[0] != "OllamaInstance" {
		t.Errorf("PROVIDES_MODEL source kinds: got %v, want [OllamaInstance]", ep.SourceKinds)
	}
	if len(ep.TargetKinds) == 0 || ep.TargetKinds[0] != "AIModel" {
		t.Errorf("PROVIDES_MODEL target kinds: got %v, want [AIModel]", ep.TargetKinds)
	}
}

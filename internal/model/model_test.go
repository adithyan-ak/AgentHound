package model

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
	if len(AllowedNodeKinds) != 12 {
		t.Errorf("AllowedNodeKinds: got %d entries, want 12", len(AllowedNodeKinds))
	}
}

func TestAllNodeLabelsComplete(t *testing.T) {
	if len(AllNodeLabels) != 14 {
		t.Errorf("AllNodeLabels: got %d entries, want 14", len(AllNodeLabels))
	}
}

func TestAllowedEdgeKindsComplete(t *testing.T) {
	if len(AllowedEdgeKinds) != 21 {
		t.Errorf("AllowedEdgeKinds: got %d entries, want 21", len(AllowedEdgeKinds))
	}
}

func TestRawEdgeKindsSubsetOfAllowed(t *testing.T) {
	for kind := range RawEdgeKinds {
		if !AllowedEdgeKinds[kind] {
			t.Errorf("RawEdgeKind %q not in AllowedEdgeKinds", kind)
		}
	}
}

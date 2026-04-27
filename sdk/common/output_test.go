package common

import (
	"strings"
	"testing"
	"time"
)

func TestNewIngestData(t *testing.T) {
	t.Run("with explicit scan ID", func(t *testing.T) {
		data := NewIngestData("mcp", "scan-mcp-123")

		if data.Meta.Version != 1 {
			t.Errorf("version = %d, want 1", data.Meta.Version)
		}
		if data.Meta.Type != "agenthound-ingest" {
			t.Errorf("type = %q, want %q", data.Meta.Type, "agenthound-ingest")
		}
		if data.Meta.Collector != "mcp" {
			t.Errorf("collector = %q, want %q", data.Meta.Collector, "mcp")
		}
		if data.Meta.CollectorVersion != CollectorVersion {
			t.Errorf("collector_version = %q, want %q", data.Meta.CollectorVersion, CollectorVersion)
		}
		if data.Meta.ScanID != "scan-mcp-123" {
			t.Errorf("scan_id = %q, want %q", data.Meta.ScanID, "scan-mcp-123")
		}
		if _, err := time.Parse(time.RFC3339, data.Meta.Timestamp); err != nil {
			t.Errorf("timestamp %q is not valid RFC3339: %v", data.Meta.Timestamp, err)
		}
		if data.Graph.Nodes == nil {
			t.Error("nodes slice is nil, want empty")
		}
		if data.Graph.Edges == nil {
			t.Error("edges slice is nil, want empty")
		}
		if len(data.Graph.Nodes) != 0 {
			t.Errorf("nodes length = %d, want 0", len(data.Graph.Nodes))
		}
		if len(data.Graph.Edges) != 0 {
			t.Errorf("edges length = %d, want 0", len(data.Graph.Edges))
		}
	})

	t.Run("with empty scan ID generates one", func(t *testing.T) {
		data := NewIngestData("config", "")

		if !strings.HasPrefix(data.Meta.ScanID, "scan-config-") {
			t.Errorf("scan_id = %q, want prefix %q", data.Meta.ScanID, "scan-config-")
		}
	})

	t.Run("different collectors", func(t *testing.T) {
		for _, collector := range []string{"mcp", "a2a", "config"} {
			data := NewIngestData(collector, "")
			if data.Meta.Collector != collector {
				t.Errorf("collector = %q, want %q", data.Meta.Collector, collector)
			}
		}
	})
}

func TestGenerateScanID(t *testing.T) {
	tests := []struct {
		collector  string
		wantPrefix string
	}{
		{"mcp", "scan-mcp-"},
		{"a2a", "scan-a2a-"},
		{"config", "scan-config-"},
	}

	for _, tt := range tests {
		t.Run(tt.collector, func(t *testing.T) {
			id := GenerateScanID(tt.collector)
			if !strings.HasPrefix(id, tt.wantPrefix) {
				t.Errorf("GenerateScanID(%q) = %q, want prefix %q", tt.collector, id, tt.wantPrefix)
			}

			uuidPart := strings.TrimPrefix(id, tt.wantPrefix)
			// UUID v4 canonical string is 36 chars (8-4-4-4-12 with hyphens).
			if len(uuidPart) != 36 {
				t.Errorf("scan ID UUID component length = %d, want 36 (canonical UUID): %q", len(uuidPart), uuidPart)
			}
		})
	}

	t.Run("uniqueness without sleep", func(t *testing.T) {
		// UUID-backed IDs should never collide, even when generated
		// in a tight loop within the same millisecond.
		seen := make(map[string]struct{}, 1000)
		for i := 0; i < 1000; i++ {
			id := GenerateScanID("mcp")
			if _, ok := seen[id]; ok {
				t.Fatalf("collision after %d iterations: %q", i, id)
			}
			seen[id] = struct{}{}
		}
	})

	t.Run("not based on time", func(t *testing.T) {
		// Smoke-check: two consecutive IDs differ even without a
		// sleep, which the old time.UnixMilli() implementation
		// could not guarantee under a fast loop.
		id1 := GenerateScanID("mcp")
		id2 := GenerateScanID("mcp")
		if id1 == id2 {
			t.Errorf("consecutive scan IDs should differ: %q == %q", id1, id2)
		}
		_ = time.Now() // keep import live
	})
}

func TestNewEdgeProps(t *testing.T) {
	props := NewEdgeProps("scan-123", 0.85, 0.3)

	if props["scan_id"] != "scan-123" {
		t.Errorf("scan_id = %v, want %q", props["scan_id"], "scan-123")
	}
	if props["confidence"] != 0.85 {
		t.Errorf("confidence = %v, want 0.85", props["confidence"])
	}
	if props["risk_weight"] != 0.3 {
		t.Errorf("risk_weight = %v, want 0.3", props["risk_weight"])
	}
	if props["is_composite"] != false {
		t.Errorf("is_composite = %v, want false", props["is_composite"])
	}
	lastSeen, ok := props["last_seen"].(string)
	if !ok {
		t.Fatal("last_seen is not a string")
	}
	if _, err := time.Parse(time.RFC3339, lastSeen); err != nil {
		t.Errorf("last_seen %q is not valid RFC3339: %v", lastSeen, err)
	}
}

func TestDefaultEdgeProps(t *testing.T) {
	props := DefaultEdgeProps("scan-456")

	if props["confidence"] != 1.0 {
		t.Errorf("confidence = %v, want 1.0", props["confidence"])
	}
	if props["risk_weight"] != 0.0 {
		t.Errorf("risk_weight = %v, want 0.0", props["risk_weight"])
	}
	if props["scan_id"] != "scan-456" {
		t.Errorf("scan_id = %v, want %q", props["scan_id"], "scan-456")
	}
}

func TestNewNode(t *testing.T) {
	t.Run("with properties", func(t *testing.T) {
		props := map[string]any{"name": "test-server", "transport": "stdio"}
		node := NewNode("sha256:abc123", []string{"MCPServer"}, props)

		if node.ID != "sha256:abc123" {
			t.Errorf("ID = %q, want %q", node.ID, "sha256:abc123")
		}
		if len(node.Kinds) != 1 || node.Kinds[0] != "MCPServer" {
			t.Errorf("Kinds = %v, want [MCPServer]", node.Kinds)
		}
		if node.Properties["objectid"] != "sha256:abc123" {
			t.Errorf("objectid = %v, want %q", node.Properties["objectid"], "sha256:abc123")
		}
		if node.Properties["name"] != "test-server" {
			t.Errorf("name = %v, want %q", node.Properties["name"], "test-server")
		}
	})

	t.Run("nil properties creates map with objectid", func(t *testing.T) {
		node := NewNode("sha256:def456", []string{"MCPTool"}, nil)

		if node.Properties == nil {
			t.Fatal("properties should not be nil")
		}
		if node.Properties["objectid"] != "sha256:def456" {
			t.Errorf("objectid = %v, want %q", node.Properties["objectid"], "sha256:def456")
		}
	})

	t.Run("objectid overwritten to match id", func(t *testing.T) {
		props := map[string]any{"objectid": "old-id"}
		node := NewNode("sha256:new-id", []string{"Host"}, props)

		if node.Properties["objectid"] != "sha256:new-id" {
			t.Errorf("objectid = %v, want %q", node.Properties["objectid"], "sha256:new-id")
		}
	})
}

func TestNewEdge(t *testing.T) {
	t.Run("with properties", func(t *testing.T) {
		props := map[string]any{"scan_id": "scan-1", "confidence": 0.9}
		edge := NewEdge("sha256:src", "sha256:tgt", "PROVIDES_TOOL", "MCPServer", "MCPTool", props)

		if edge.Source != "sha256:src" {
			t.Errorf("Source = %q, want %q", edge.Source, "sha256:src")
		}
		if edge.Target != "sha256:tgt" {
			t.Errorf("Target = %q, want %q", edge.Target, "sha256:tgt")
		}
		if edge.Kind != "PROVIDES_TOOL" {
			t.Errorf("Kind = %q, want %q", edge.Kind, "PROVIDES_TOOL")
		}
		if edge.Properties["scan_id"] != "scan-1" {
			t.Errorf("scan_id = %v, want %q", edge.Properties["scan_id"], "scan-1")
		}
	})

	t.Run("nil properties creates empty map", func(t *testing.T) {
		edge := NewEdge("sha256:a", "sha256:b", "TRUSTS_SERVER", "AgentInstance", "MCPServer", nil)

		if edge.Properties == nil {
			t.Fatal("properties should not be nil")
		}
	})
}

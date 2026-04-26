package ingest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestValidateTestDataFiles(t *testing.T) {
	v := NewValidator()

	validFiles := []struct {
		file      string
		nodeCount int
		edgeCount int
	}{
		{"valid_mcp_scan.json", 5, 4},
		{"valid_config_scan.json", 7, 8},
		{"valid_a2a_scan.json", 5, 4},
		{"valid_merged_scan.json", -1, -1}, // count varies
	}

	testdataDir := filepath.Join("..", "..", "testdata")

	for _, tc := range validFiles {
		path := filepath.Join(testdataDir, tc.file)
		data, err := os.ReadFile(path)
		if err != nil {
			// Try alternate name for merged
			if tc.file == "valid_merged_scan.json" {
				path = filepath.Join(testdataDir, "merged_scan.json")
				data, err = os.ReadFile(path)
			}
			if err != nil {
				t.Logf("skipping %s: %v", tc.file, err)
				continue
			}
		}

		var d ingest.IngestData
		if err := json.Unmarshal(data, &d); err != nil {
			t.Errorf("%s: parse error: %v", tc.file, err)
			continue
		}

		if err := v.Validate(&d); err != nil {
			t.Errorf("%s: validation failed: %v", tc.file, err)
			continue
		}

		if tc.nodeCount > 0 && len(d.Graph.Nodes) != tc.nodeCount {
			t.Errorf("%s: expected %d nodes, got %d", tc.file, tc.nodeCount, len(d.Graph.Nodes))
		}
		if tc.edgeCount > 0 && len(d.Graph.Edges) != tc.edgeCount {
			t.Errorf("%s: expected %d edges, got %d", tc.file, tc.edgeCount, len(d.Graph.Edges))
		}
	}
}

func TestInvalidTestDataRejected(t *testing.T) {
	v := NewValidator()
	testdataDir := filepath.Join("..", "..", "testdata")

	data, err := os.ReadFile(filepath.Join(testdataDir, "invalid_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	var d ingest.IngestData
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	err = v.Validate(&d)
	if err == nil {
		t.Fatal("expected validation error for invalid_scan.json")
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}

	if len(ve.Errors) < 3 {
		t.Errorf("expected at least 3 validation errors, got %d: %+v", len(ve.Errors), ve.Errors)
	}
}

func TestMCPServerIDMergePoint(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")

	mcpData, err := os.ReadFile(filepath.Join(testdataDir, "valid_mcp_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}
	cfgData, err := os.ReadFile(filepath.Join(testdataDir, "valid_config_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	var mcp, cfg ingest.IngestData
	if err := json.Unmarshal(mcpData, &mcp); err != nil {
		t.Fatalf("parse mcp: %v", err)
	}
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	// Find MCPServer IDs in both scans
	mcpServerIDs := make(map[string]bool)
	for _, n := range mcp.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "MCPServer" {
				mcpServerIDs[n.ID] = true
			}
		}
	}

	cfgServerIDs := make(map[string]bool)
	for _, n := range cfg.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "MCPServer" {
				cfgServerIDs[n.ID] = true
			}
		}
	}

	// At least one MCPServer ID must be the same across both scans
	overlap := 0
	for id := range mcpServerIDs {
		if cfgServerIDs[id] {
			overlap++
		}
	}

	if overlap == 0 {
		t.Errorf("no MCPServer IDs match between mcp and config scans\nmcp: %v\nconfig: %v", mcpServerIDs, cfgServerIDs)
	}
}

func TestNormalizerWithTestData(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")
	data, err := os.ReadFile(filepath.Join(testdataDir, "valid_mcp_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	var d ingest.IngestData
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("parse: %v", err)
	}

	n := NewNormalizer()
	n.Normalize(&d)

	// Every node must have objectid set
	for _, node := range d.Graph.Nodes {
		if node.Properties["objectid"] != node.ID {
			t.Errorf("node %s: objectid mismatch: %v != %v", node.ID, node.Properties["objectid"], node.ID)
		}
	}

	// No nil values in properties
	for _, node := range d.Graph.Nodes {
		for k, v := range node.Properties {
			if v == nil {
				t.Errorf("node %s: nil value for key %q", node.ID, k)
			}
		}
	}
}

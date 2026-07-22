package ingest

import (
	"strings"
	"testing"
)

func TestDecodeStrictRejectsUnknownStructuralField(t *testing.T) {
	var data IngestData
	err := DecodeStrict(strings.NewReader(`{
		"meta": {
			"version": 4,
			"type": "agenthound-ingest",
			"identity": {},
			"collector": "mcp",
			"collector_version": "0.1.0",
			"timestamp": "2026-04-06T10:30:00Z",
			"scan_id": "scan-1",
			"unexpected": true
		},
		"graph": {"nodes": [], "edges": []}
	}`), &data)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeStrict() error = %v, want unknown-field rejection", err)
	}
}

func TestDecodeStrictAllowsCollectorProperties(t *testing.T) {
	var data IngestData
	err := DecodeStrict(strings.NewReader(`{
		"meta": {
			"version": 4,
			"type": "agenthound-ingest",
			"identity": {},
			"collector": "mcp",
			"collector_version": "0.1.0",
			"timestamp": "2026-04-06T10:30:00Z",
			"scan_id": "scan-1"
		},
		"graph": {
			"nodes": [{
				"id": "node",
				"kinds": ["MCPServer"],
				"properties": {"collector_specific": true}
			}],
			"edges": []
		}
	}`), &data)
	if err != nil {
		t.Fatalf("DecodeStrict() rejected open property map: %v", err)
	}
}

func TestDecodeStrictRejectsTrailingValue(t *testing.T) {
	var data IngestData
	err := DecodeStrict(
		strings.NewReader(`{"meta":{},"graph":{}} {"extra":true}`),
		&data,
	)
	if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("DecodeStrict() error = %v, want trailing-value rejection", err)
	}
}

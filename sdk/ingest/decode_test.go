package ingest

import (
	"strings"
	"testing"
)

func TestDecodeVersionReadsOpenEnvelope(t *testing.T) {
	version, err := DecodeVersion([]byte(`{
		"meta": {"version": 1, "unrelated_meta_field": true},
		"unrelated_top_level_field": {"nested": true}
	}`))
	if err != nil {
		t.Fatalf("DecodeVersion() error = %v", err)
	}
	if version != 1 {
		t.Fatalf("version = %d, want 1", version)
	}
}

func TestDecodeVersionRejectsMalformedEnvelope(t *testing.T) {
	if _, err := DecodeVersion([]byte(`{"meta":`)); err == nil {
		t.Fatal("DecodeVersion() accepted malformed JSON")
	}
	if _, err := DecodeVersion([]byte(`{"graph":{}}`)); err == nil {
		t.Fatal("DecodeVersion() accepted missing meta")
	}
}

func TestDecodeStrictRejectsUnknownStructuralField(t *testing.T) {
	var data IngestData
	err := DecodeStrict(strings.NewReader(`{
		"meta": {
			"version": 1,
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
			"version": 1,
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

func TestDecodeStrictRejectsRemovedAdvisoryField(t *testing.T) {
	var data IngestData
	err := DecodeStrict(strings.NewReader(`{
		"meta": {
			"version": 1,
			"type": "agenthound-ingest",
			"identity": {},
			"collector": "config",
			"collector_version": "0.1.0",
			"timestamp": "2026-04-06T10:30:00Z",
			"scan_id": "scan-1",
			"collection": {
				"state": "truncated",
				"coverage_keys": ["config:instruction-deep:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
				"outcomes": [{
					"collector": "config",
					"coverage_key": "config:instruction-deep:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"target": "/home/example",
					"method": "instruction_deep",
					"state": "truncated",
					"advisory": true
				}]
			}
		},
		"graph": {"nodes": [], "edges": []}
	}`), &data)
	if err == nil || !strings.Contains(err.Error(), `unknown field "advisory"`) {
		t.Fatalf("DecodeStrict() error = %v, want removed advisory-field rejection", err)
	}
}

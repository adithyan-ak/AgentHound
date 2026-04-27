package common

import (
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/google/uuid"
)

const CollectorVersion = "0.1.0"

func NewIngestData(collector, scanID string) *ingest.IngestData {
	if scanID == "" {
		scanID = GenerateScanID(collector)
	}
	return &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        collector,
			CollectorVersion: CollectorVersion,
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			ScanID:           scanID,
		},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{},
			Edges: []ingest.Edge{},
		},
	}
}

// GenerateScanID returns a globally unique identifier for a scan.
//
// Format: "scan-<collector>-<uuid-v4>". The UUID component eliminates
// collisions when two collectors run in the same millisecond on the
// same machine (the prior time.UnixMilli() form had visible collisions
// in fast-loop tests). The collector prefix is preserved because tools
// downstream (UI, scan history, log greppers) parse it.
func GenerateScanID(collector string) string {
	return fmt.Sprintf("scan-%s-%s", collector, uuid.NewString())
}

func NewEdgeProps(scanID string, confidence, riskWeight float64) map[string]any {
	return map[string]any{
		"scan_id":      scanID,
		"last_seen":    time.Now().UTC().Format(time.RFC3339),
		"confidence":   confidence,
		"risk_weight":  riskWeight,
		"is_composite": false,
	}
}

func DefaultEdgeProps(scanID string) map[string]any {
	return NewEdgeProps(scanID, 1.0, 0.0)
}

func NewNode(id string, kinds []string, props map[string]any) ingest.Node {
	if props == nil {
		props = make(map[string]any)
	}
	props["objectid"] = id
	return ingest.Node{
		ID:         id,
		Kinds:      kinds,
		Properties: props,
	}
}

func NewEdge(source, target, kind, sourceKind, targetKind string, props map[string]any) ingest.Edge {
	if props == nil {
		props = make(map[string]any)
	}
	return ingest.Edge{
		Source:     source,
		Target:     target,
		Kind:       kind,
		SourceKind: sourceKind,
		TargetKind: targetKind,
		Properties: props,
	}
}

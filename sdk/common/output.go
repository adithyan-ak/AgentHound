package common

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/google/uuid"
)

const DefaultCollectorVersion = "dev"

var collectorVersion atomic.Value

func init() {
	collectorVersion.Store(DefaultCollectorVersion)
}

func CollectorVersion() string {
	version, ok := collectorVersion.Load().(string)
	if !ok || version == "" {
		return DefaultCollectorVersion
	}
	return version
}

func SetCollectorVersion(version string) {
	if version = strings.TrimSpace(version); version != "" {
		collectorVersion.Store(version)
	}
}

// ResolveBuildInfo returns the version and commit reported by the binaries.
// GoReleaser's linker values take precedence. A go install build has the
// development linker defaults but records its module version in Go build
// metadata, so use that version when available and leave the commit unknown.
func ResolveBuildInfo(version, commit string) (string, string) {
	return resolveBuildInfo(version, commit, debug.ReadBuildInfo)
}

func resolveBuildInfo(version, commit string, readBuildInfo func() (*debug.BuildInfo, bool)) (string, string) {
	version = strings.TrimSpace(version)
	commit = strings.TrimSpace(commit)
	if version == "" {
		version = DefaultCollectorVersion
	}
	if commit == "" {
		commit = "none"
	}

	if version != DefaultCollectorVersion || commit != "none" {
		return strings.TrimPrefix(version, "v"), commit
	}

	info, ok := readBuildInfo()
	if !ok || info == nil || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return version, commit
	}
	return strings.TrimPrefix(info.Main.Version, "v"), commit
}

func NewIngestData(collector, scanID string) *ingest.IngestData {
	if scanID == "" {
		scanID = GenerateScanID(collector)
	}
	return &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          ingest.CurrentVersion,
			Type:             ingest.IngestType,
			Collector:        collector,
			CollectorVersion: CollectorVersion(),
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			ScanID:           scanID,
			Ruleset:          ingest.EmptyRulesetManifest(),
			IdentitySchemes:  ingest.CurrentIdentitySchemes(),
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

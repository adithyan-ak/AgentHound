package ingest

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

const (
	historicalV1Fixture = "v1-tag-1.1.0-valid-mcp.json"
	// This digest records the byte-for-byte provenance of
	// testdata/valid_mcp_scan.json at the immutable 1.1.0 tag.
	historicalV1FixtureSHA256 = "8ce201b5dfcf2ccb8269d327ad565209a6593a9a20c5a11ef2c5b09a3436b35d"
)

func decodeHistoricalV1Fixture(t *testing.T) *sdkingest.IngestData {
	t.Helper()
	path := filepath.Join("testdata", "compat", historicalV1Fixture)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read historical V1 fixture: %v", err)
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(document)); digest != historicalV1FixtureSHA256 {
		t.Fatalf("historical V1 fixture digest = %s, want %s", digest, historicalV1FixtureSHA256)
	}

	var data sdkingest.IngestData
	if err := sdkingest.DecodeStrict(bytes.NewReader(document), &data); err != nil {
		t.Fatalf("strictly decode historical V1 fixture: %v", err)
	}
	return &data
}

func TestHistoricalV1Tag110FixtureRemainsCompatible(t *testing.T) {
	data := decodeHistoricalV1Fixture(t)
	if data.Meta.Version != sdkingest.CurrentVersion {
		t.Fatalf("artifact contract = V%d, want V%d", data.Meta.Version, sdkingest.CurrentVersion)
	}
	if data.Meta.CollectorVersion != "0.1.0" {
		t.Fatalf("collector version = %q, want historical 0.1.0", data.Meta.CollectorVersion)
	}
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("validate historical V1 fixture: %v", err)
	}
}

func TestIntegrationHistoricalV1Tag110Publishes(t *testing.T) {
	ctx, pipeline, _, _, _ := publicationIntegrationHarness(t, false)
	data := decodeHistoricalV1Fixture(t)

	result, err := pipeline.Ingest(ctx, data)
	if err != nil {
		t.Fatalf("ingest historical V1 fixture: %v", err)
	}
	if result.Outcome != sdkingest.OutcomeComplete ||
		result.ProjectionStatus != model.ProjectionComplete ||
		result.PublishedRevision == nil {
		t.Fatalf("historical V1 publication result = %+v", result)
	}
}

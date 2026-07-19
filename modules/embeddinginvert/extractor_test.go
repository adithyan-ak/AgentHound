package embeddinginvert

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestExtract_UpstreamFixtureExactInventory(t *testing.T) {
	sourceID := ingest.ComputeNodeID("AIModel", "upstream-instance", "upstream-model")
	res, err := (&Extractor{}).Extract(context.Background(), action.Target{
		Kind: "node", Address: sourceID,
	}, action.ExtractOptions{
		SourceNodeID: sourceID, ArtifactPath: upstreamFixturePath(), EngagementID: "UPSTREAM-TEST",
		Extras: map[string]any{"confidence-threshold": 1.0},
	})
	if err != nil {
		t.Fatalf("Extract upstream fixture: %v", err)
	}
	if res.Summary.ArtifactsProduced != 2 || len(res.IngestData.Graph.Nodes) != 3 || len(res.IngestData.Graph.Edges) != 2 {
		t.Fatalf("inventory = summary:%d nodes:%d edges:%d, want 2/3/2",
			res.Summary.ArtifactsProduced, len(res.IngestData.Graph.Nodes), len(res.IngestData.Graph.Edges))
	}
	ref := res.IngestData.Graph.Nodes[0]
	if ref.ID != sourceID || len(ref.Kinds) != 1 || ref.Kinds[0] != "AIModel" ||
		ref.PropertySemantics != ingest.NodePropertySemanticsReferenceOnly || len(ref.Properties) != 0 {
		t.Fatalf("source reference = %+v, want empty reference_only AIModel", ref)
	}
	wantTokens := []string{"[upstream_signal]", "[upstream_tool]"}
	wantIndices := []int{4, 5}
	wantMagnitudes := []float64{6.303967005, 8.303011503}
	for i, node := range res.IngestData.Graph.Nodes[1:] {
		if node.Properties["source_model_id"] != sourceID || node.Properties["engagement_id"] != "UPSTREAM-TEST" || node.Properties["method"] != "embedding-outlier" {
			t.Errorf("node %d provenance = %+v", i, node.Properties)
		}
		if node.Properties["token_index"] != wantIndices[i] || node.Properties["token_string"] != wantTokens[i] {
			t.Errorf("node %d signal = index:%v token:%v", i, node.Properties["token_index"], node.Properties["token_string"])
		}
		if got, _ := node.Properties["magnitude"].(float64); math.Abs(got-wantMagnitudes[i]) > 1e-5 {
			t.Errorf("node %d magnitude = %.9f, want %.9f", i, got, wantMagnitudes[i])
		}
		edge := res.IngestData.Graph.Edges[i]
		if edge.Source != sourceID || edge.Target != node.ID || edge.Kind != "EXTRACTED_FROM" || edge.Properties["method"] != "embedding-outlier" {
			t.Errorf("edge %d = %+v", i, edge)
		}
	}
}

func TestExtract_DetectsOutliers(t *testing.T) {
	e := &Extractor{}
	sourceID := ingest.ComputeNodeID("AIModel", "test-instance", "test-model")
	res, err := e.Extract(context.Background(), action.Target{
		Kind:    "node",
		Address: sourceID,
	}, action.ExtractOptions{
		SourceNodeID: sourceID,
		ArtifactPath: fixturePath(),
		EngagementID: "TEST-001",
		DryRun:       false,
		Extras:       map[string]any{"confidence-threshold": 1.5},
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.IngestData == nil {
		t.Fatal("IngestData nil")
	}
	if res.Summary.ArtifactsProduced < 2 {
		t.Errorf("expected at least 2 outliers (rows 8+9), got %d", res.Summary.ArtifactsProduced)
	}

	var foundSecret, foundTool bool
	for _, n := range res.IngestData.Graph.Nodes {
		tok, _ := n.Properties["token_string"].(string)
		switch tok {
		case "[fine_tune_secret]":
			foundSecret = true
		case "[internal_tool_xyz]":
			foundTool = true
		}
	}
	if !foundSecret {
		t.Error("outlier token [fine_tune_secret] not detected")
	}
	if !foundTool {
		t.Error("outlier token [internal_tool_xyz] not detected")
	}

	if len(res.IngestData.Graph.Edges) != res.Summary.ArtifactsProduced {
		t.Errorf("edges (%d) != artifacts (%d)", len(res.IngestData.Graph.Edges), res.Summary.ArtifactsProduced)
	}
	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind != "EXTRACTED_FROM" {
			t.Errorf("edge kind = %q, want EXTRACTED_FROM", e.Kind)
		}
		if e.SourceKind != "AIModel" || e.TargetKind != "ExtractedTrainingSignal" {
			t.Errorf("edge endpoints: %s -> %s", e.SourceKind, e.TargetKind)
		}
	}
}

func TestExtract_DryRunEmitsNoData(t *testing.T) {
	e := &Extractor{}
	sourceID := ingest.ComputeNodeID("AIModel", "test-instance", "test-model")
	res, err := e.Extract(context.Background(), action.Target{
		Kind:    "node",
		Address: sourceID,
	}, action.ExtractOptions{
		SourceNodeID: sourceID,
		ArtifactPath: fixturePath(),
		EngagementID: "TEST-002",
		DryRun:       true,
		Extras:       map[string]any{"confidence-threshold": 1.5},
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.IngestData != nil {
		t.Error("DryRun should not produce IngestData")
	}
	if !res.Summary.DryRun {
		t.Error("Summary.DryRun should be true")
	}
	if res.Summary.ArtifactsProduced < 2 {
		t.Errorf("dry-run should still count outliers: got %d", res.Summary.ArtifactsProduced)
	}
}

func TestExtract_MissingArtifact(t *testing.T) {
	e := &Extractor{}
	_, err := e.Extract(context.Background(), action.Target{}, action.ExtractOptions{
		ArtifactPath: "/nonexistent.gguf",
		EngagementID: "X",
	})
	if err == nil {
		t.Error("expected error on missing artifact")
	}
}

func TestExtract_RequiresArtifactPath(t *testing.T) {
	e := &Extractor{}
	_, err := e.Extract(context.Background(), action.Target{}, action.ExtractOptions{
		EngagementID: "X",
	})
	if err == nil {
		t.Error("expected error when --artifact not provided")
	}
}

func TestExtract_RejectsNonCanonicalSourceNodeID(t *testing.T) {
	e := &Extractor{}
	_, err := e.Extract(context.Background(), action.Target{
		Kind:    "node",
		Address: "hf://example/model.gguf",
	}, action.ExtractOptions{
		SourceNodeID: "hf://example/model.gguf",
		ArtifactPath: fixturePath(),
		EngagementID: "TEST-NODE-ID",
	})
	if err == nil || !strings.Contains(err.Error(), "source node ID must be sha256:") {
		t.Fatalf("invalid source node ID error = %v", err)
	}
}

func TestExtract_Q8_0_DetectsOutliers(t *testing.T) {
	e := &Extractor{}
	sourceID := ingest.ComputeNodeID("AIModel", "q8-instance", "q8-model")
	res, err := e.Extract(context.Background(), action.Target{
		Kind:    "node",
		Address: sourceID,
	}, action.ExtractOptions{
		SourceNodeID: sourceID,
		ArtifactPath: q8FixturePath(),
		EngagementID: "Q8-TEST",
		DryRun:       false,
		Extras:       map[string]any{"confidence-threshold": 1.5},
	})
	if err != nil {
		t.Fatalf("Extract Q8_0: %v", err)
	}
	if res.IngestData == nil {
		t.Fatal("IngestData nil")
	}
	if res.Summary.ArtifactsProduced < 2 {
		t.Errorf("expected at least 2 Q8_0 outliers (rows 8+9), got %d", res.Summary.ArtifactsProduced)
	}
	var foundSecret bool
	for _, n := range res.IngestData.Graph.Nodes {
		if tok, _ := n.Properties["token_string"].(string); tok == "[secret_finetune_token]" {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Error("Q8_0 outlier token [secret_finetune_token] not detected")
	}
}

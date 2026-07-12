package embeddinginvert

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// Extractor implements the embedding-inversion PoC. It parses a GGUF
// weight file, computes per-row L2 norms on the embedding matrix, and
// flags statistical outliers (z-score above threshold) as likely
// fine-tune additions. When tokenizer vocabulary is present in the GGUF
// metadata, outlier indices are mapped to token strings.
type Extractor struct{}

// RegisterFlags satisfies module.FlagsModule.
func (e *Extractor) RegisterFlags(fs *pflag.FlagSet) {
	fs.Float64("confidence-threshold", 3.0,
		"Z-score threshold for flagging an embedding as an outlier (default 3.0).")
	fs.Int("max-signals", 1000,
		"Maximum number of ExtractedTrainingSignal nodes to emit.")
}

// Extract runs the embedding-inversion pipeline against the artifact
// at opts.ArtifactPath. Returns ingest data with ExtractedTrainingSignal
// nodes and EXTRACTED_FROM edges.
func (e *Extractor) Extract(ctx context.Context, t action.Target, opts action.ExtractOptions) (*action.ExtractResult, error) {
	if opts.ArtifactPath == "" {
		return nil, fmt.Errorf("embedding extract: --artifact <path> is required")
	}
	threshold := 3.0
	if v, ok := opts.Extras["confidence-threshold"].(float64); ok && v > 0 {
		threshold = v
	}
	maxSignals := 1000
	if v, ok := opts.Extras["max-signals"].(int); ok && v > 0 {
		maxSignals = v
	}
	sourceNodeID := opts.SourceNodeID

	slog.Info("embedding extract: parsing GGUF", "path", opts.ArtifactPath)
	gguf, err := ParseGGUF(opts.ArtifactPath)
	if err != nil {
		return nil, fmt.Errorf("parse gguf: %w", err)
	}
	slog.Info("embedding extract: parsed",
		"vocab_size", gguf.VocabSize,
		"embed_dim", gguf.EmbedDim,
		"tokenizer_tokens", len(gguf.Tokens))

	// Compute L2 norms for each embedding row.
	norms := make([]float64, gguf.VocabSize)
	for i, row := range gguf.Embeddings {
		var sum float64
		for _, v := range row {
			sum += float64(v) * float64(v)
		}
		norms[i] = math.Sqrt(sum)
	}

	// Compute mean and stddev of norms.
	var sumNorm, sumSq float64
	for _, n := range norms {
		sumNorm += n
		sumSq += n * n
	}
	mean := sumNorm / float64(len(norms))
	variance := sumSq/float64(len(norms)) - mean*mean
	if variance < 0 {
		variance = 0
	}
	stddev := math.Sqrt(variance)

	if stddev == 0 {
		return &action.ExtractResult{
			Summary: action.ExtractSummary{DryRun: opts.DryRun},
		}, nil
	}

	var signals []signal
	for i, n := range norms {
		z := (n - mean) / stddev
		if z >= threshold {
			tok := ""
			if i < len(gguf.Tokens) {
				tok = gguf.Tokens[i]
			}
			signals = append(signals, signal{
				Index:  i,
				Token:  tok,
				Norm:   n,
				ZScore: z,
			})
			if len(signals) >= maxSignals {
				break
			}
		}
	}

	slog.Info("embedding extract: analysis complete",
		"mean_norm", fmt.Sprintf("%.3f", mean),
		"stddev", fmt.Sprintf("%.3f", stddev),
		"outliers_found", len(signals),
		"threshold", threshold)

	if opts.DryRun {
		return &action.ExtractResult{
			Summary: action.ExtractSummary{
				ArtifactsProduced: len(signals),
				Confidence:        avgConfidence(collectZScores(signals), threshold),
				DryRun:            true,
			},
		}, nil
	}

	// Build ingest payload.
	out := &ingest.IngestData{}
	for _, sig := range signals {
		confidence := math.Min(sig.ZScore/threshold, 1.0)
		nodeID := ingest.ComputeNodeID("ExtractedTrainingSignal", sourceNodeID, fmt.Sprintf("%d", sig.Index))
		out.Graph.Nodes = append(out.Graph.Nodes, ingest.Node{
			ID:    nodeID,
			Kinds: []string{"ExtractedTrainingSignal"},
			Properties: map[string]any{
				"objectid":        nodeID,
				"token_index":     sig.Index,
				"token_string":    sig.Token,
				"magnitude":       sig.Norm,
				"z_score":         sig.ZScore,
				"confidence":      confidence,
				"source_model_id": sourceNodeID,
				"engagement_id":   opts.EngagementID,
				"method":          "embedding-outlier",
				"extracted_at":    time.Now().UTC().Format(time.RFC3339),
			},
		})
		out.Graph.Edges = append(out.Graph.Edges, ingest.Edge{
			Source:     sourceNodeID,
			Target:     nodeID,
			Kind:       "EXTRACTED_FROM",
			SourceKind: "AIModel",
			TargetKind: "ExtractedTrainingSignal",
			Properties: map[string]any{
				"confidence":  confidence,
				"risk_weight": 0.1,
				"method":      "embedding-outlier",
				"evidence": map[string]any{
					"z_score":       sig.ZScore,
					"magnitude":     sig.Norm,
					"mean_norm":     mean,
					"engagement_id": opts.EngagementID,
				},
			},
		})
	}

	return &action.ExtractResult{
		IngestData: out,
		Summary: action.ExtractSummary{
			ArtifactsProduced: len(signals),
			Confidence:        avgConfidence(collectZScores(signals), threshold),
			DryRun:            false,
		},
	}, nil
}

type signal struct {
	Index  int
	Token  string
	Norm   float64
	ZScore float64
}

func collectZScores(signals []signal) []float64 {
	out := make([]float64, len(signals))
	for i, s := range signals {
		out[i] = s.ZScore
	}
	return out
}

func avgConfidence(zScores []float64, threshold float64) float64 {
	if len(zScores) == 0 {
		return 0
	}
	var sum float64
	for _, z := range zScores {
		sum += math.Min(z/threshold, 1.0)
	}
	return sum / float64(len(zScores))
}

var _ action.Extractor = (*Extractor)(nil)

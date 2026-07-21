package action

import (
	"context"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// Extractor analyzes a specific resource supplied by reference (a known file
// path, memory region, table, etc.). It is distinct from Looter, which performs
// broader target collection. The current embedding-inversion implementation
// performs local analysis and does not mutate or consume compute on the target.
//
// The embedding-inversion Extractor takes an AIModel node + a GGUF weight file
// the operator has already obtained by other means (filesystem access to
// ~/.ollama/models/blobs/
// on a compromised Ollama host, a HuggingFace download, or any other
// out-of-band source) and runs a local embedding-inversion algorithm
// to produce probabilistic training-signal artifacts. AgentHound does
// not itself pull raw weight blobs over HTTP — the previous Ollama
// Looter --include-weights path was withdrawn because the endpoint it
// targeted (GET /api/blobs/<digest>) does not exist in the Ollama API.
//
// Implementations also implement sdk/module.Module.
type Extractor interface {
	Extract(ctx context.Context, t Target, opts ExtractOptions) (*ExtractResult, error)
}

// ExtractOptions configures a single extract dispatch.
type ExtractOptions struct {
	// SourceNodeID is the objectid of the node we're extracting from
	// (e.g. an AIModel node produced by the Ollama Looter).
	SourceNodeID string

	// ArtifactPath is the local filesystem path to an artifact the
	// Extractor consumes — for embedding-invert, any GGUF weight file
	// the operator has already obtained (e.g. copied from
	// ~/.ollama/models/blobs/ on a compromised host, downloaded from
	// HuggingFace, or produced by another tool).
	ArtifactPath string

	// EngagementID correlates the extraction with the engagement.
	EngagementID string

	// DryRun=true runs the extraction pipeline end-to-end but does not emit
	// ingest data. The --commit flag is an output gate, not an execution or
	// target-mutation gate.
	DryRun bool

	// Extras carries per-Extractor flag values, same pattern as
	// LootOptions.Extras and PoisonPayload.Extras.
	Extras map[string]any
}

// ExtractResult carries the ingest payload the Extractor would emit,
// plus diagnostic metadata for the CLI's summary line.
type ExtractResult struct {
	IngestData *ingest.IngestData
	Summary    ExtractSummary
}

// ExtractSummary is what the CLI prints after an extract dispatch.
type ExtractSummary struct {
	ArtifactsProduced int
	Confidence        float64
	DryRun            bool
}

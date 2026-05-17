package action

import (
	"context"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// Extractor pulls a specific resource by reference (a known file path,
// memory region, table, etc.) from a Target. Distinct from Looter, which
// performs broader untargeted collection. Extractors are computationally
// heavy and potentially destructive in the billing sense (they may
// consume inference compute on the target) — gated behind --commit like
// Poisoners.
//
// v0.4 ships one proof-of-concept Extractor: embedding-inversion. It
// takes an AIModel node + extracted weights from the Ollama Looter's
// --include-weights path and runs a local embedding-inversion algorithm
// to produce probabilistic training-signal artifacts.
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
	// Extractor consumes (e.g. a weight file previously downloaded by
	// `agenthound loot --type ollama --include-weights`).
	ArtifactPath string

	// EngagementID correlates the extraction with the engagement.
	EngagementID string

	// DryRun=true runs the extraction pipeline end-to-end but does not
	// persist results or emit ingest data. Useful for profiling
	// resource consumption before committing.
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

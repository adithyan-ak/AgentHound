package action

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// ServiceCollector performs provider-specific, read-oriented collection after
// discovery has identified a concrete service. It may use protocol-required
// read-only POSTs; state mutation is outside this contract.
type ServiceCollector interface {
	Collect(context.Context, Target, CollectOptions) (*CollectResult, error)
}

type CollectOptions struct {
	Credentials map[string]string
	MaxItems    int
	Timeout     time.Duration
	Extras      map[string]any
}

type CollectResult struct {
	IngestData *ingest.IngestData
	// Inventory describes the exhaustive membership surface owned by this
	// service collection. The autonomous planner converts it into one stable,
	// service-instance coverage outcome. Probe/enrichment failures may still be
	// reported through PartialErrors without making a successfully enumerated
	// membership surface incomplete.
	Inventory     *InventoryResult
	PartialErrors []string
	Summary       CollectSummary
}

// InventoryResult reports whether a service-owned inventory was exhaustive.
// Name is a stable, non-secret surface identifier such as "collections" or
// "contents"; it is combined with the service node ID to derive coverage.
type InventoryResult struct {
	Name  string
	State ingest.OutcomeState
	Items int
	Error string
}

type CollectSummary struct {
	EndpointsProbed  int
	CredentialsFound int
	PartialFailures  int
}

func (r *CollectResult) ToIngest() *ingest.IngestData {
	if r == nil || r.IngestData == nil {
		return &ingest.IngestData{}
	}
	return r.IngestData
}

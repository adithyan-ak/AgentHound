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
	IngestData    *ingest.IngestData
	PartialErrors []string
	Summary       CollectSummary
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

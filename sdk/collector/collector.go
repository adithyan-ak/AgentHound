package collector

import (
	"context"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context, opts CollectOptions) (*ingest.IngestData, error)
}

type CollectOptions struct {
	ConfigPath              string
	ConfigPaths             []string
	TargetURL               string
	TargetURLs              []string
	TargetURLsFile          string
	Discover                bool
	ProjectDir              string
	OutputPath              string
	Concurrency             int
	Timeout                 time.Duration
	IncludeCredentialValues bool
	Insecure                bool
	AuthToken               string
	ScanID                  string
	RulesEngine             *rules.Engine // nil = default engine constructed automatically
}

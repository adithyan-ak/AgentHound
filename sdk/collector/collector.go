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
	// InstructionRecursiveRoot names the canonical home boundary used only by
	// optional nested registered-source discovery. Empty disables deep traversal;
	// exact registered sources at user and project roots are still collected.
	InstructionRecursiveRoot string
	// InstructionDeep enables bounded nested discovery. Directory, matched-file,
	// byte, and wall-clock limits make its incomplete state non-blocking while
	// preserving explicit coverage limitations.
	InstructionDeep bool
}

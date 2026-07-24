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
	// InstructionRecursiveRoot enables the recursive .cursor/rules instruction
	// walk and names the directory it starts from. Empty disables the walk
	// entirely (the default host scan never crawls the filesystem). Fixed
	// single-file instruction targets are read regardless of this field.
	InstructionRecursiveRoot string
	// InstructionDeep selects best-effort mode for the recursive walk: a larger
	// entry cap plus a wall-clock budget, and advisory coverage so a truncated
	// sweep still publishes instead of withholding the projection.
	InstructionDeep bool
}

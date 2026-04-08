package collector

import (
	"context"

	"github.com/adithyan-ak/agenthound/internal/model"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context, opts CollectOptions) (*model.IngestData, error)
}

type CollectOptions struct {
	ConfigPath string
	TargetURL  string
	TargetURLs []string
	Discover   bool
}

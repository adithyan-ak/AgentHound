package analysis

import (
	"context"

	"github.com/adithyan-ak/agenthound/internal/graph"
)

type PostProcessor interface {
	Name() string
	DependsOn() []string
	Process(ctx context.Context, reader *graph.Reader, writer *graph.Writer) error
}

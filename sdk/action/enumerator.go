package action

import (
	"context"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// Enumerator is the reserved action contract for inspecting one Target and
// producing a graph patch. The current CLI does not dispatch this interface;
// Config, MCP, and A2A runtime work uses sdk/collector.Collector directly.
//
// Implementations also implement sdk/module.Module.
type Enumerator interface {
	Enumerate(ctx context.Context, t Target, opts EnumerateOptions) (*ingest.IngestData, error)
}

// EnumerateOptions is currently empty because no CLI path dispatches
// Enumerator. Adding options is an explicit public API change.
type EnumerateOptions struct{}

package graph

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestEdgeKindEndpointsCoversAllEdgeKinds(t *testing.T) {
	for kind := range ingest.AllowedEdgeKinds {
		if _, ok := ingest.EdgeKindEndpoints[kind]; !ok {
			t.Errorf("EdgeKindEndpoints missing entry for edge kind %q", kind)
		}
	}
	for kind := range ingest.EdgeKindEndpoints {
		if !ingest.AllowedEdgeKinds[kind] {
			t.Errorf("EdgeKindEndpoints has extra entry for unknown edge kind %q", kind)
		}
	}
}

package graph

import (
	"testing"

	"github.com/adithyan-ak/agenthound/internal/model"
)

func TestEdgeKindCypherCoversAllEdgeKinds(t *testing.T) {
	keys := EdgeKindCypherKeys()
	for kind := range model.AllowedEdgeKinds {
		if !keys[kind] {
			t.Errorf("edgeKindCypher missing entry for edge kind %q", kind)
		}
	}
	for kind := range keys {
		if !model.AllowedEdgeKinds[kind] {
			t.Errorf("edgeKindCypher has extra entry for unknown edge kind %q", kind)
		}
	}
}

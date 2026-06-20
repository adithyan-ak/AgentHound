package analysis

import (
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/analysis/prebuilt"
)

// TestATLASTags_FindingsMetaValid guards against shipping an invalid
// AML.Txxxx tag: every atlas tag referenced by findingsMeta must resolve to a
// known technique in ATLASTechniques.
func TestATLASTags_FindingsMetaValid(t *testing.T) {
	for edgeKind, meta := range findingsMeta {
		for _, tag := range meta.atlas {
			if _, ok := ATLASTechniques[tag]; !ok {
				t.Errorf("findingsMeta[%q] references unknown ATLAS technique %q", edgeKind, tag)
			}
		}
	}
}

// TestATLASTags_PrebuiltValid guards the same invariant for pre-built queries.
func TestATLASTags_PrebuiltValid(t *testing.T) {
	for id, q := range prebuilt.Registry {
		for _, tag := range q.ATLASMap {
			if _, ok := ATLASTechniques[tag]; !ok {
				t.Errorf("prebuilt query %q references unknown ATLAS technique %q", id, tag)
			}
		}
	}
}

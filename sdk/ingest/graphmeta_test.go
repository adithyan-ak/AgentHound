package ingest

import "testing"

// TestNodeKindMetadataMatchesLabels guards that the presentation metadata table
// stays in lockstep with the canonical node-label registry — the generator and
// the UI depend on every label having exactly one metadata entry.
func TestNodeKindMetadataMatchesLabels(t *testing.T) {
	if len(NodeKindMetadata) != len(AllNodeLabels) {
		t.Fatalf("NodeKindMetadata has %d entries, AllNodeLabels has %d", len(NodeKindMetadata), len(AllNodeLabels))
	}
	for _, label := range AllNodeLabels {
		m, ok := NodeKindMetaFor(label)
		if !ok {
			t.Errorf("NodeKindMetadata missing entry for label %q", label)
			continue
		}
		if m.CollectorProduced != AllowedNodeKinds[label] {
			t.Errorf("%s: CollectorProduced=%t but AllowedNodeKinds=%t", label, m.CollectorProduced, AllowedNodeKinds[label])
		}
		if m.Umbrella != UmbrellaLabels[label] {
			t.Errorf("%s: Umbrella=%t but UmbrellaLabels=%t", label, m.Umbrella, UmbrellaLabels[label])
		}
	}
}

// TestEdgeKindMetadataMatchesRegistry guards that every allowed edge kind has
// metadata, that the composite flag agrees with raw-vs-composite membership,
// that each edge has an endpoint contract, and that its lens is a known lens.
func TestEdgeKindMetadataMatchesRegistry(t *testing.T) {
	if len(EdgeKindMetadata) != len(AllowedEdgeKinds) {
		t.Fatalf("EdgeKindMetadata has %d entries, AllowedEdgeKinds has %d", len(EdgeKindMetadata), len(AllowedEdgeKinds))
	}
	lenses := make(map[LensCategory]bool, len(AllLensCategories))
	for _, l := range AllLensCategories {
		lenses[l] = true
	}
	for kind := range AllowedEdgeKinds {
		m, ok := EdgeKindMetaFor(kind)
		if !ok {
			t.Errorf("EdgeKindMetadata missing entry for edge %q", kind)
			continue
		}
		wantComposite := !RawEdgeKinds[kind]
		if m.Composite != wantComposite {
			t.Errorf("%s: Composite=%t, want %t (raw=%t)", kind, m.Composite, wantComposite, RawEdgeKinds[kind])
		}
		if !lenses[m.Lens] {
			t.Errorf("%s: unknown lens %q", kind, m.Lens)
		}
		if m.Description == "" {
			t.Errorf("%s: empty description", kind)
		}
		if _, ok := EdgeKindEndpoints[kind]; !ok {
			t.Errorf("%s: no EdgeKindEndpoints entry", kind)
		}
	}
}

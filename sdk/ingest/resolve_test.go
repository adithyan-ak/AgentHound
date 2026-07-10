package ingest

import "testing"

func TestResolveEdgeEndpoints_KnownKind(t *testing.T) {
	src, tgt := ResolveEdgeEndpoints("PROVIDES_TOOL", "", "")
	if src != "MCPServer" {
		t.Errorf("source: got %q, want %q", src, "MCPServer")
	}
	if tgt != "MCPTool" {
		t.Errorf("target: got %q, want %q", tgt, "MCPTool")
	}
}

func TestResolveEdgeEndpoints_UnknownKind(t *testing.T) {
	src, tgt := ResolveEdgeEndpoints("MADE_UP_KIND", "", "")
	if src != "" {
		t.Errorf("source: got %q, want empty", src)
	}
	if tgt != "" {
		t.Errorf("target: got %q, want empty", tgt)
	}
}

func TestResolveEdgeEndpoints_ExplicitOverride(t *testing.T) {
	src, tgt := ResolveEdgeEndpoints("PROVIDES_TOOL", "CustomSource", "CustomTarget")
	if src != "CustomSource" {
		t.Errorf("source: got %q, want %q", src, "CustomSource")
	}
	if tgt != "CustomTarget" {
		t.Errorf("target: got %q, want %q", tgt, "CustomTarget")
	}
}

func TestResolveEdgeEndpoints_PartialOverrideSource(t *testing.T) {
	src, tgt := ResolveEdgeEndpoints("PROVIDES_TOOL", "CustomSource", "")
	if src != "CustomSource" {
		t.Errorf("source: got %q, want %q", src, "CustomSource")
	}
	if tgt != "MCPTool" {
		t.Errorf("target: got %q, want %q (registry fallback)", tgt, "MCPTool")
	}
}

func TestResolveEdgeEndpoints_PartialOverrideTarget(t *testing.T) {
	src, tgt := ResolveEdgeEndpoints("PROVIDES_TOOL", "", "CustomTarget")
	if src != "MCPServer" {
		t.Errorf("source: got %q, want %q (registry fallback)", src, "MCPServer")
	}
	if tgt != "CustomTarget" {
		t.Errorf("target: got %q, want %q", tgt, "CustomTarget")
	}
}

func TestResolveEdgeEndpoints_AllRegisteredKindsResolvable(t *testing.T) {
	for kind, ep := range EdgeKindEndpoints {
		src, tgt := ResolveEdgeEndpoints(kind, "", "")
		if src == "" {
			t.Errorf("%s: source resolved to empty (registry has %v)", kind, ep.SourceKinds)
		}
		if tgt == "" {
			t.Errorf("%s: target resolved to empty (registry has %v)", kind, ep.TargetKinds)
		}
	}
}

// TestProvidesResource_AcceptsMLflowAndQdrantSources locks in the
// extension of PROVIDES_RESOURCE to accept :MCPResource emissions from
// mlflowloot (Model Registry storage URIs) and qdrantloot (scrolled
// point payloads) in addition to the original MCPServer and
// JupyterServer sources.
func TestProvidesResource_AcceptsMLflowAndQdrantSources(t *testing.T) {
	ep, ok := EdgeKindEndpoints["PROVIDES_RESOURCE"]
	if !ok {
		t.Fatal("PROVIDES_RESOURCE missing from EdgeKindEndpoints")
	}
	wantSources := map[string]bool{
		"MCPServer": true, "JupyterServer": true,
		"MLflowServer": true, "QdrantInstance": true,
	}
	got := map[string]bool{}
	for _, s := range ep.SourceKinds {
		got[s] = true
	}
	for k := range wantSources {
		if !got[k] {
			t.Errorf("PROVIDES_RESOURCE source-kinds missing %q; got %v", k, ep.SourceKinds)
		}
	}
	// Explicit-override paths for both new sources.
	for _, src := range []string{"MLflowServer", "QdrantInstance"} {
		gotSrc, gotTgt := ResolveEdgeEndpoints("PROVIDES_RESOURCE", src, "MCPResource")
		if gotSrc != src || gotTgt != "MCPResource" {
			t.Errorf("ResolveEdgeEndpoints(PROVIDES_RESOURCE, %q, MCPResource) = (%q, %q), want (%q, MCPResource)",
				src, gotSrc, gotTgt, src)
		}
	}
}

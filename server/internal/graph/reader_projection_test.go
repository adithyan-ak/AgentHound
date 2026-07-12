package graph

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// TestMergeObservations_CollectorAuthorityWins is the F4 counterexample:
// conflict resolution must use a DETERMINISTIC, MEANINGFUL precedence
// (collector authority) rather than "greatest (random UUID) generation_id".
// The config observation here carries the lexicographically-GREATER
// generation_id, which under the old rule would have won arbitrarily; the mcp
// observation (higher collector authority) must win instead.
func TestMergeObservations_CollectorAuthorityWins(t *testing.T) {
	// config has the greater generation_id ("gen-zzz" > "gen-aaa") so the old
	// UUID-ordering rule would pick config. Authority must override that.
	cfg := physObservation{
		props:  map[string]any{"generation_id": "gen-zzz", "source_collector": "config", "shared": "from-config"},
		labels: []string{"MCPServer"},
	}
	mcp := physObservation{
		props:  map[string]any{"generation_id": "gen-aaa", "source_collector": "mcp", "shared": "from-mcp"},
		labels: []string{"MCPServer"},
	}
	for _, order := range [][]physObservation{{cfg, mcp}, {mcp, cfg}} {
		merged := mergeObservations("S", order)
		if merged.Properties["shared"] != "from-mcp" {
			t.Errorf("conflict winner = %v, want from-mcp (mcp outranks config regardless of generation_id)", merged.Properties["shared"])
		}
	}
}

// TestMergeObservations_CaptureTimeTieBreak verifies the second precedence
// level: with equal collector authority, the later capture time wins.
func TestMergeObservations_CaptureTimeTieBreak(t *testing.T) {
	older := physObservation{
		props: map[string]any{"generation_id": "gen-zzz", "source_collector": "mcp", "captured_at": "2026-01-01T00:00:00Z", "shared": "older"},
	}
	newer := physObservation{
		props: map[string]any{"generation_id": "gen-aaa", "source_collector": "mcp", "captured_at": "2026-06-01T00:00:00Z", "shared": "newer"},
	}
	merged := mergeObservations("S", []physObservation{older, newer})
	if merged.Properties["shared"] != "newer" {
		t.Errorf("conflict winner = %v, want newer (later capture wins at equal authority)", merged.Properties["shared"])
	}
}

// TestPickEdgeRepresentative_Deterministic is the F4 counterexample for edge
// representative selection: among physical observations of one logical triple,
// the highest-authority edge is chosen regardless of input order — not the
// arbitrary first-collected row.
func TestPickEdgeRepresentative_Deterministic(t *testing.T) {
	cfgEdge := ingest.Edge{Source: "a", Kind: "TRUSTS_SERVER", Target: "b", Properties: map[string]any{
		"source_collector": "config", "generation_id": "gen-zzz", "marker": "config",
	}}
	mcpEdge := ingest.Edge{Source: "a", Kind: "TRUSTS_SERVER", Target: "b", Properties: map[string]any{
		"source_collector": "mcp", "generation_id": "gen-aaa", "marker": "mcp",
	}}
	for _, order := range [][]ingest.Edge{{cfgEdge, mcpEdge}, {mcpEdge, cfgEdge}} {
		rep := pickEdgeRepresentative(order)
		if rep.Properties["marker"] != "mcp" {
			t.Errorf("edge representative = %v, want mcp (higher authority)", rep.Properties["marker"])
		}
	}
	// dedupEdgesLogical collapses to one representative per triple.
	out := dedupEdgesLogical([]ingest.Edge{cfgEdge, mcpEdge})
	if len(out) != 1 {
		t.Fatalf("dedupEdgesLogical returned %d edges, want 1", len(out))
	}
	if out[0].Properties["marker"] != "mcp" {
		t.Errorf("deduped representative = %v, want mcp", out[0].Properties["marker"])
	}
}

// TestMergeObservations_DeterministicConflict verifies the logical-current
// projection (F2): observations of the same objectid merge into one node,
// unioning properties, with a DETERMINISTIC winner (greatest generation_id) for
// conflicting keys — regardless of the order the observations arrive in.
func TestMergeObservations_DeterministicConflict(t *testing.T) {
	obsCfg := physObservation{
		props:  map[string]any{"generation_id": "gen-aaa", "observation_id": "gen-aaa\x1fS", "cfg_only": "c", "shared": "from-cfg"},
		labels: []string{"MCPServer"},
	}
	obsMcp := physObservation{
		props:  map[string]any{"generation_id": "gen-bbb", "observation_id": "gen-bbb\x1fS", "mcp_only": "m", "shared": "from-mcp", "cap": "x"},
		labels: []string{"MCPServer", "AIService"},
	}

	// Both orders must produce the identical merged node.
	forward := mergeObservations("S", []physObservation{obsCfg, obsMcp})
	reverse := mergeObservations("S", []physObservation{obsMcp, obsCfg})

	for _, m := range []struct {
		name string
		node ingest.Node
	}{{"forward", forward}, {"reverse", reverse}} {
		if m.node.ID != "S" {
			t.Errorf("%s: id = %q, want S", m.name, m.node.ID)
		}
		// Union of keys.
		if m.node.Properties["cfg_only"] != "c" || m.node.Properties["mcp_only"] != "m" || m.node.Properties["cap"] != "x" {
			t.Errorf("%s: properties not unioned: %v", m.name, m.node.Properties)
		}
		// Deterministic winner: gen-bbb > gen-aaa, so "from-mcp" wins.
		if m.node.Properties["shared"] != "from-mcp" {
			t.Errorf("%s: conflict winner = %v, want from-mcp (greatest generation_id)", m.name, m.node.Properties["shared"])
		}
		// Labels unioned; primary kind stays first.
		if len(m.node.Kinds) == 0 || m.node.Kinds[0] != "MCPServer" {
			t.Errorf("%s: primary kind = %v, want MCPServer first", m.name, m.node.Kinds)
		}
		if !containsStr(m.node.Kinds, "AIService") {
			t.Errorf("%s: labels not unioned: %v", m.name, m.node.Kinds)
		}
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

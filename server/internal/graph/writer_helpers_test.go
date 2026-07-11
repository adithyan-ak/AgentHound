package graph

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestGroupNodesByKind(t *testing.T) {
	t.Run("multiple kinds grouped correctly", func(t *testing.T) {
		nodes := []ingest.Node{
			{ID: "a1", Kinds: []string{"MCPServer"}},
			{ID: "a2", Kinds: []string{"MCPTool"}},
			{ID: "a3", Kinds: []string{"MCPServer"}},
			{ID: "a4", Kinds: []string{"MCPTool"}},
			{ID: "a5", Kinds: []string{"A2AAgent"}},
		}
		grouped := groupNodesByKind(nodes)

		if len(grouped) != 3 {
			t.Fatalf("expected 3 groups, got %d", len(grouped))
		}
		if len(grouped["MCPServer"]) != 2 {
			t.Errorf("MCPServer: expected 2 nodes, got %d", len(grouped["MCPServer"]))
		}
		if len(grouped["MCPTool"]) != 2 {
			t.Errorf("MCPTool: expected 2 nodes, got %d", len(grouped["MCPTool"]))
		}
		if len(grouped["A2AAgent"]) != 1 {
			t.Errorf("A2AAgent: expected 1 node, got %d", len(grouped["A2AAgent"]))
		}
	})

	t.Run("empty slice returns empty map", func(t *testing.T) {
		grouped := groupNodesByKind(nil)
		if len(grouped) != 0 {
			t.Errorf("expected empty map, got %d entries", len(grouped))
		}
	})

	t.Run("node with no kinds defaults to Node label", func(t *testing.T) {
		nodes := []ingest.Node{
			{ID: "x1", Kinds: nil},
			{ID: "x2", Kinds: []string{}},
		}
		grouped := groupNodesByKind(nodes)

		if len(grouped) != 1 {
			t.Fatalf("expected 1 group, got %d", len(grouped))
		}
		if len(grouped["Node"]) != 2 {
			t.Errorf("expected 2 nodes under 'Node', got %d", len(grouped["Node"]))
		}
	})

	t.Run("uses first kind when node has multiple kinds", func(t *testing.T) {
		nodes := []ingest.Node{
			{ID: "m1", Kinds: []string{"MCPServer", "Host"}},
		}
		grouped := groupNodesByKind(nodes)

		if _, ok := grouped["MCPServer"]; !ok {
			t.Fatal("expected node grouped under first kind 'MCPServer'")
		}
		if _, ok := grouped["Host"]; ok {
			t.Error("node should not appear under second kind 'Host'")
		}
	})

	t.Run("preserves node identity", func(t *testing.T) {
		nodes := []ingest.Node{
			{ID: "p1", Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "test"}},
		}
		grouped := groupNodesByKind(nodes)

		n := grouped["MCPServer"][0]
		if n.ID != "p1" {
			t.Errorf("expected ID 'p1', got %q", n.ID)
		}
		val, ok := n.Properties["name"]
		if !ok {
			t.Fatal("expected 'name' property")
		}
		s, ok := val.(string)
		if !ok {
			t.Fatal("expected string property value")
		}
		if s != "test" {
			t.Errorf("expected 'test', got %q", s)
		}
	})
}

func TestGroupEdgesByEndpoints(t *testing.T) {
	t.Run("groups by kind and resolved endpoints", func(t *testing.T) {
		edges := []ingest.Edge{
			{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
			{Source: "s2", Target: "t2", Kind: "PROVIDES_TOOL"},
			{Source: "s3", Target: "t3", Kind: "TRUSTS_SERVER"},
		}
		grouped := groupEdgesByEndpoints(edges)

		if len(grouped) != 2 {
			t.Fatalf("expected 2 groups, got %d", len(grouped))
		}

		ptKey := edgeGroupKey{Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool"}
		if len(grouped[ptKey]) != 2 {
			t.Errorf("PROVIDES_TOOL: expected 2 edges, got %d", len(grouped[ptKey]))
		}

		tsKey := edgeGroupKey{Kind: "TRUSTS_SERVER", SourceKind: "AgentInstance", TargetKind: "MCPServer"}
		if len(grouped[tsKey]) != 1 {
			t.Errorf("TRUSTS_SERVER: expected 1 edge, got %d", len(grouped[tsKey]))
		}
	})

	t.Run("empty slice returns empty map", func(t *testing.T) {
		grouped := groupEdgesByEndpoints(nil)
		if len(grouped) != 0 {
			t.Errorf("expected empty map, got %d entries", len(grouped))
		}
	})

	t.Run("explicit SourceKind and TargetKind override registry", func(t *testing.T) {
		edges := []ingest.Edge{
			{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL", SourceKind: "CustomSource", TargetKind: "CustomTarget"},
		}
		grouped := groupEdgesByEndpoints(edges)

		customKey := edgeGroupKey{Kind: "PROVIDES_TOOL", SourceKind: "CustomSource", TargetKind: "CustomTarget"}
		if len(grouped[customKey]) != 1 {
			t.Error("expected edge grouped under explicit custom kinds")
		}
	})

	t.Run("unknown edge kind with no explicit kinds uses empty strings", func(t *testing.T) {
		edges := []ingest.Edge{
			{Source: "s1", Target: "t1", Kind: "UNKNOWN_EDGE"},
		}
		grouped := groupEdgesByEndpoints(edges)

		unknownKey := edgeGroupKey{Kind: "UNKNOWN_EDGE", SourceKind: "", TargetKind: ""}
		if len(grouped[unknownKey]) != 1 {
			t.Error("expected edge grouped with empty source/target kinds")
		}
	})

	t.Run("same kind but different endpoint kinds create separate groups", func(t *testing.T) {
		edges := []ingest.Edge{
			{Source: "s1", Target: "t1", Kind: "RUNS_ON", SourceKind: "MCPServer", TargetKind: "Host"},
			{Source: "s2", Target: "t2", Kind: "RUNS_ON", SourceKind: "A2AAgent", TargetKind: "Host"},
		}
		grouped := groupEdgesByEndpoints(edges)

		if len(grouped) != 2 {
			t.Fatalf("expected 2 groups for different source kinds, got %d", len(grouped))
		}
	})
}

func TestMatchClause(t *testing.T) {
	t.Run("with kind includes label", func(t *testing.T) {
		got := matchClause("a", "MCPServer", "source")
		want := "MATCH (a:MCPServer {objectid: edge.source})"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("without kind omits label", func(t *testing.T) {
		got := matchClause("a", "", "source")
		want := "MATCH (a {objectid: edge.source})"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("target field", func(t *testing.T) {
		got := matchClause("b", "MCPTool", "target")
		want := "MATCH (b:MCPTool {objectid: edge.target})"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestEdgeCypherForKinds(t *testing.T) {
	t.Run("PROVIDES_TOOL generates correct cypher", func(t *testing.T) {
		cypher := edgeCypherForKinds("PROVIDES_TOOL", "MCPServer", "MCPTool")

		if !strings.Contains(cypher, "UNWIND $edges AS edge") {
			t.Error("missing UNWIND clause")
		}
		if !strings.Contains(cypher, "MATCH (a:MCPServer {objectid: edge.source})") {
			t.Error("missing source MATCH with MCPServer label")
		}
		if !strings.Contains(cypher, "MATCH (b:MCPTool {objectid: edge.target})") {
			t.Error("missing target MATCH with MCPTool label")
		}
		if !strings.Contains(cypher, "MERGE (a)-[r:PROVIDES_TOOL]->(b)") {
			t.Error("missing MERGE with PROVIDES_TOOL relationship")
		}
		if !strings.Contains(cypher, "r += edge.properties") {
			t.Error("missing SET clause for properties")
		}
		if !strings.Contains(cypher, "r.scan_id = $scan_id") {
			t.Error("missing scan_id assignment")
		}
		if !strings.Contains(cypher, "RETURN count(*) AS written") {
			t.Error("missing RETURN clause")
		}
	})

	t.Run("empty source and target kinds omit labels", func(t *testing.T) {
		cypher := edgeCypherForKinds("CUSTOM_EDGE", "", "")

		if !strings.Contains(cypher, "MATCH (a {objectid: edge.source})") {
			t.Error("expected label-free source MATCH")
		}
		if !strings.Contains(cypher, "MATCH (b {objectid: edge.target})") {
			t.Error("expected label-free target MATCH")
		}
		if !strings.Contains(cypher, "MERGE (a)-[r:CUSTOM_EDGE]->(b)") {
			t.Error("missing MERGE with CUSTOM_EDGE")
		}
	})

	t.Run("mixed: source kind set, target kind empty", func(t *testing.T) {
		cypher := edgeCypherForKinds("RUNS_ON", "MCPServer", "")

		if !strings.Contains(cypher, "MATCH (a:MCPServer {objectid: edge.source})") {
			t.Error("expected labeled source MATCH")
		}
		if !strings.Contains(cypher, "MATCH (b {objectid: edge.target})") {
			t.Error("expected label-free target MATCH")
		}
	})
}

// TestGroupNodesByKindTuple is the v0.2 multi-label regression guard. The
// design (kinds.go: AIService umbrella, schema.go: skip umbrella constraints,
// writer.go: MERGE on per-kind + SET umbrella) only works if the writer's
// grouping function produces a separate Cypher template for every distinct
// (primary, sorted-extras) tuple.
func TestGroupNodesByKindTuple(t *testing.T) {
	t.Run("single-label nodes group by primary kind", func(t *testing.T) {
		nodes := []ingest.Node{
			{ID: "a1", Kinds: []string{"MCPServer"}},
			{ID: "a2", Kinds: []string{"MCPServer"}},
			{ID: "a3", Kinds: []string{"MCPTool"}},
		}
		grouped := groupNodesByKindTuple(nodes)

		if len(grouped) != 2 {
			t.Fatalf("expected 2 groups, got %d", len(grouped))
		}
		mcpSrv, ok := grouped["MCPServer"]
		if !ok {
			t.Fatal("missing MCPServer group")
		}
		if mcpSrv.PrimaryKind != "MCPServer" || len(mcpSrv.ExtraLabels) != 0 || len(mcpSrv.Nodes) != 2 {
			t.Errorf("MCPServer: got primary=%q extras=%v nodes=%d, want MCPServer/[]/2",
				mcpSrv.PrimaryKind, mcpSrv.ExtraLabels, len(mcpSrv.Nodes))
		}
	})

	t.Run("multi-label nodes group by primary+sorted-extras", func(t *testing.T) {
		nodes := []ingest.Node{
			{ID: "g1", Kinds: []string{"LiteLLMGateway", "AIService"}},
			{ID: "g2", Kinds: []string{"LiteLLMGateway", "AIService"}},
			{ID: "o1", Kinds: []string{"OllamaInstance", "AIService"}},
		}
		grouped := groupNodesByKindTuple(nodes)

		if len(grouped) != 2 {
			t.Fatalf("expected 2 groups, got %d", len(grouped))
		}
		litellm, ok := grouped["LiteLLMGateway+AIService"]
		if !ok {
			t.Fatal("missing LiteLLMGateway+AIService group")
		}
		if litellm.PrimaryKind != "LiteLLMGateway" {
			t.Errorf("primary: got %q, want LiteLLMGateway", litellm.PrimaryKind)
		}
		if len(litellm.ExtraLabels) != 1 || litellm.ExtraLabels[0] != "AIService" {
			t.Errorf("extras: got %v, want [AIService]", litellm.ExtraLabels)
		}
		if len(litellm.Nodes) != 2 {
			t.Errorf("nodes: got %d, want 2", len(litellm.Nodes))
		}
	})

	t.Run("kinds [A,B] and [B,A] are NOT merged (primary kind matters)", func(t *testing.T) {
		// LiteLLMGateway+AIService and AIService+LiteLLMGateway encode different
		// primary kinds. The first uses LiteLLMGateway as the merge key (correct);
		// the second uses AIService as the merge key (incorrect — umbrella has no
		// uniqueness constraint). They MUST stay distinct so a malformed emitter
		// can't silently pollute graphs.
		nodes := []ingest.Node{
			{ID: "ok", Kinds: []string{"LiteLLMGateway", "AIService"}},
			{ID: "bad", Kinds: []string{"AIService", "LiteLLMGateway"}},
		}
		grouped := groupNodesByKindTuple(nodes)
		if len(grouped) != 2 {
			t.Fatalf("expected 2 groups, got %d", len(grouped))
		}
	})

	t.Run("empty Kinds defaults to Node primary", func(t *testing.T) {
		nodes := []ingest.Node{{ID: "x", Kinds: nil}}
		grouped := groupNodesByKindTuple(nodes)
		if g, ok := grouped["Node"]; !ok || g.PrimaryKind != "Node" {
			t.Errorf("expected Node group, got %v", grouped)
		}
	})
}

func TestNodeCypherForKindTuple(t *testing.T) {
	t.Run("single-label produces a plain MERGE", func(t *testing.T) {
		c := nodeCypherForKindTuple("MCPServer", nil)
		if !strings.Contains(c, "MERGE (n:MCPServer {objectid: node.id})") {
			t.Errorf("expected MERGE on MCPServer; got:\n%s", c)
		}
		if strings.Contains(c, "SET n:") {
			t.Errorf("expected no extra SET n:Label clauses for single-label node; got:\n%s", c)
		}
	})

	t.Run("multi-label appends SET n:Label per umbrella", func(t *testing.T) {
		c := nodeCypherForKindTuple("LiteLLMGateway", []string{"AIService"})
		if !strings.Contains(c, "MERGE (n:LiteLLMGateway {objectid: node.id})") {
			t.Errorf("MERGE primary: got:\n%s", c)
		}
		if !strings.Contains(c, "SET n:AIService") {
			t.Errorf("missing SET n:AIService; got:\n%s", c)
		}
		if !strings.Contains(c, "RETURN count(*) AS written") {
			t.Errorf("missing RETURN; got:\n%s", c)
		}
	})

	t.Run("multiple umbrella labels stack", func(t *testing.T) {
		c := nodeCypherForKindTuple("LiteLLMGateway", []string{"AIService", "Reachable"})
		if !strings.Contains(c, "SET n:AIService") {
			t.Error("missing SET n:AIService")
		}
		if !strings.Contains(c, "SET n:Reachable") {
			t.Error("missing SET n:Reachable")
		}
	})
}

// TestWriteNodes_MultiLabel asserts the end-to-end behavior via the in-memory
// execFn recorder: a multi-label node produces exactly one Cypher batch whose
// statement contains both the per-kind MERGE and the umbrella SET. This is
// the regression guard that catches a future refactor that might silently
// drop umbrella labels and break the credential-chain demo.
func TestWriteNodes_MultiLabel(t *testing.T) {
	var captured []string
	w := &Writer{
		batchSize: defaultBatchSize,
		execFn: func(_ context.Context, cypher string, _ map[string]any) (int, error) {
			captured = append(captured, cypher)
			return 1, nil
		},
	}

	nodes := []ingest.Node{
		{ID: "sha256:llm1", Kinds: []string{"LiteLLMGateway", "AIService"},
			Properties: map[string]any{"endpoint": "http://lab:4000"}},
	}
	written, err := w.WriteNodes(context.Background(), nodes, "scan-multilabel-test")
	if err != nil {
		t.Fatalf("WriteNodes: %v", err)
	}
	if written != 1 {
		t.Errorf("written: got %d, want 1", written)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 cypher batch, got %d", len(captured))
	}
	c := captured[0]
	if !strings.Contains(c, "MERGE (n:LiteLLMGateway {objectid: node.id})") {
		t.Errorf("missing MERGE on LiteLLMGateway; cypher:\n%s", c)
	}
	if !strings.Contains(c, "SET n:AIService") {
		t.Errorf("missing SET n:AIService; cypher:\n%s", c)
	}
}

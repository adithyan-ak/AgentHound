package prebuilt

import (
	"strings"
	"testing"
)

func TestGet_ValidID(t *testing.T) {
	q, ok := Get("agents-shell-access")
	if !ok {
		t.Fatal("expected to find agents-shell-access query")
	}
	if q.Cypher == "" {
		t.Fatal("expected non-empty Cypher for agents-shell-access")
	}
	if q.ID != "agents-shell-access" {
		t.Fatalf("expected ID agents-shell-access, got %q", q.ID)
	}
}

func TestGet_InvalidID(t *testing.T) {
	_, ok := Get("nonexistent")
	if ok {
		t.Fatal("expected false for nonexistent query ID")
	}
}

func TestList_Count(t *testing.T) {
	queries := List()
	// 17 v0.1 + 1 v0.2 (litellm-credential-leak) + 1 (tool-name-collision) = 19.
	if len(queries) != 19 {
		t.Fatalf("expected 19 pre-built queries, got %d", len(queries))
	}
}

// TestLitellmCredentialLeak_Registered guards the v0.2 acceptance
// criterion: the new prebuilt query is wired through the registry,
// shows up in List(), is fetchable via Get(), and points at a
// non-empty Cypher constant.
func TestLitellmCredentialLeak_Registered(t *testing.T) {
	q, ok := Get("litellm-credential-leak")
	if !ok {
		t.Fatal("litellm-credential-leak missing from Registry")
	}
	if q.Category != "Critical Paths" {
		t.Errorf("Category = %q, want Critical Paths", q.Category)
	}
	if q.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", q.Severity)
	}
	if q.Name != "Observed LiteLLM Master-Key Exposure" {
		t.Errorf("Name = %q", q.Name)
	}
	if !strings.Contains(q.Description, "masked/hashed references only") ||
		!strings.Contains(q.Description, "do not claim usable") {
		t.Errorf("Description overstates upstream evidence: %q", q.Description)
	}
	if q.Cypher == "" {
		t.Error("Cypher must not be empty")
	}
	wantOWASP := map[string]bool{"MCP03": true, "ASI04": true}
	for _, m := range q.OWASPMap {
		delete(wantOWASP, m)
	}
	if len(wantOWASP) != 0 {
		t.Errorf("OWASPMap = %v, want MCP03 + ASI04", q.OWASPMap)
	}
}

func TestList_AllHaveCypher(t *testing.T) {
	for _, q := range List() {
		if q.Cypher == "" {
			t.Errorf("query %q has empty Cypher", q.ID)
		}
	}
}

func TestList_AllHaveCategory(t *testing.T) {
	for _, q := range List() {
		if q.Category == "" {
			t.Errorf("query %q has empty Category", q.ID)
		}
	}
}

func TestShortestToDatabaseFallbackIsDirectedAndScoped(t *testing.T) {
	if strings.Contains(CypherShortestToDatabase, "]-(") {
		t.Fatal("shortest-to-database must not use an undirected relationship pattern")
	}
	if !strings.Contains(CypherShortestToDatabase, "]->(r)") {
		t.Fatal("shortest-to-database must follow outgoing relationships")
	}
	for _, kind := range []string{"TRUSTS_SERVER", "PROVIDES_TOOL", "HAS_ACCESS_TO"} {
		if !strings.Contains(CypherShortestToDatabase, kind) {
			t.Fatalf("shortest-to-database relationship scope missing %s", kind)
		}
	}
}

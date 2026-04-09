package prebuilt

import "testing"

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
	if len(queries) != 17 {
		t.Fatalf("expected 17 pre-built queries, got %d", len(queries))
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

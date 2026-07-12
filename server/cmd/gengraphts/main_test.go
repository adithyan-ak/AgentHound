package main

import (
	"bytes"
	"os"
	"testing"
)

// TestGeneratedTSUpToDate guards against the canonical TypeScript registry
// drifting from the Go source of truth. `render()` is deterministic, so the
// committed server/ui/src/entities/graph/generated.ts must byte-match a fresh
// render. If this fails, a node/edge kind, endpoint, lens, or enum changed in
// sdk/ingest or sdk/common without regenerating — the UI's dto.ts would then
// export stale unions. Regenerate with:
//
//	go run ./server/cmd/gengraphts
func TestGeneratedTSUpToDate(t *testing.T) {
	got := render()

	path := defaultOutPath()
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed generated.ts (%s): %v", path, err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale relative to the Go graph registry.\n"+
			"Regenerate it with: go run ./server/cmd/gengraphts", path)
	}
}

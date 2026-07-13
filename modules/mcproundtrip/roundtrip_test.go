package mcproundtrip

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

// mcpStub is a stateful tools/list + tool-update stub mirroring the mcppoison
// test harness, so the REAL mcppoison-backed round-trip runs end to end against
// a live HTTP surface rather than a fake.
func mcpStub(t *testing.T, initial string) (*httptest.Server, func() string) {
	t.Helper()
	var (
		mu      sync.Mutex
		current = initial
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/":
			mu.Lock()
			desc := current
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			body, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"tools": []map[string]any{
					{"name": testTargetID, "description": desc},
				}},
			})
			_, _ = w.Write(body)
		case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/admin/tools/"):
			b, _ := io.ReadAll(r.Body)
			defer func() { _ = r.Body.Close() }()
			var parsed struct {
				Description string `json:"description"`
			}
			if err := json.Unmarshal(b, &parsed); err != nil {
				w.WriteHeader(400)
				return
			}
			mu.Lock()
			current = parsed.Description
			mu.Unlock()
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	return srv, func() string { mu.Lock(); defer mu.Unlock(); return current }
}

// TestRealRoundtrip_HappyPath drives the REAL mcppoison Poison + conflict-aware
// Revert (no fake) against a live stub, proving genuine reuse: the mutation
// lands (oracle verified), the original is restored (cleanup restored), and the
// target is confirmed back at its original description.
func TestRealRoundtrip_HappyPath(t *testing.T) {
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())
	srv, getCurrent := mcpStub(t, origDesc)
	defer srv.Close()

	s := &Scenario{} // nil newRoundTrip => real mcppoison-backed factory
	res, err := s.Run(context.Background(), campaign.RunInput{
		Host:         srv.URL,
		EngagementID: "ENG-REAL",
		Commit:       true,
		Params: map[string]string{
			"target-id": testTargetID,
			"inject":    injDesc,
			"mode":      "replace",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep := res.Roundtrip
	if rep == nil {
		t.Fatal("expected a round-trip report")
	}
	if rep.Oracle != campaign.OracleMutationVerified {
		t.Errorf("oracle = %q, want mutation_verified", rep.Oracle)
	}
	if rep.Cleanup != campaign.CleanupRestored {
		t.Errorf("cleanup = %q, want restored", rep.Cleanup)
	}
	if !rep.TargetClean() {
		t.Error("target must be reported clean after a successful round-trip")
	}
	if got := getCurrent(); got != origDesc {
		t.Errorf("target left at %q, want original %q", got, origDesc)
	}
}

// TestRealRoundtrip_ConflictCleanup proves the conflict-aware revert does not
// blind-write against a live surface: a third-party edit landing after the
// mutation makes the revert refuse, so cleanup=conflict and the third-party
// value is preserved. The stub flips to a third-party value once it has served
// the mutation write and the oracle read.
func TestRealRoundtrip_ConflictCleanup(t *testing.T) {
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())

	const thirdParty = "THIRD-PARTY DESCRIPTION"
	var (
		mu       sync.Mutex
		current  = origDesc
		putCount int
		listGET  int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/":
			mu.Lock()
			listGET++
			// Reads in order: 1=poison original, 2=oracle. After the oracle read
			// a third party edits the tool, so the revert's own re-read (3) sees
			// a value matching neither original nor injected -> conflict.
			if listGET >= 3 {
				current = thirdParty
			}
			desc := current
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			body, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"tools": []map[string]any{
					{"name": testTargetID, "description": desc},
				}},
			})
			_, _ = w.Write(body)
		case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/admin/tools/"):
			b, _ := io.ReadAll(r.Body)
			defer func() { _ = r.Body.Close() }()
			var parsed struct {
				Description string `json:"description"`
			}
			if err := json.Unmarshal(b, &parsed); err != nil {
				w.WriteHeader(400)
				return
			}
			mu.Lock()
			current = parsed.Description
			putCount++
			mu.Unlock()
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	s := &Scenario{}
	res, err := s.Run(context.Background(), campaign.RunInput{
		Host:         srv.URL,
		EngagementID: "ENG-CONFLICT",
		Commit:       true,
		Params: map[string]string{
			"target-id": testTargetID,
			"inject":    injDesc,
			"mode":      "replace",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep := res.Roundtrip
	if rep.Oracle != campaign.OracleMutationVerified {
		t.Errorf("oracle = %q, want mutation_verified (mutation landed before the third-party edit)", rep.Oracle)
	}
	if rep.Cleanup != campaign.CleanupConflict {
		t.Errorf("cleanup = %q, want conflict", rep.Cleanup)
	}
	if rep.TargetClean() {
		t.Error("a conflicted cleanup must not report the target as clean")
	}
	mu.Lock()
	defer mu.Unlock()
	// Exactly one PUT (the mutation). The conflict-aware revert must not write.
	if putCount != 1 {
		t.Errorf("PUT count = %d, want 1 (revert must not blind-write on conflict)", putCount)
	}
	if current != thirdParty {
		t.Errorf("target = %q, want the preserved third-party value %q", current, thirdParty)
	}
}

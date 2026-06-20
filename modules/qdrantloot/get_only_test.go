package qdrantloot

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestLooter_HTTPMethods enforces the Looter contract (sdk/action.Looter):
// no state-mutating requests. The Qdrant Looter is PURE GET — its
// inventory probes (/collections and /collections/{name}) are plain GETs
// with no body, so there should be NO POST/PUT/PATCH/DELETE/CONNECT call
// site at all. Any future addition (e.g. a POST search/scroll query) must
// be added to the allowlist below WITH a comment explaining why it is
// read-only-in-effect, or this guard fails.
//
// Mirrors modules/mlflowloot/get_only_test.go and
// modules/ollamaloot/get_only_test.go.
func TestLooter_HTTPMethods(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "looter.go"))
	if err != nil {
		t.Fatalf("read looter.go: %v", err)
	}

	mutating := regexp.MustCompile(`"(POST|PUT|PATCH|DELETE|CONNECT)"`)
	matches := mutating.FindAllStringIndex(string(src), -1)
	if matches == nil {
		return // Pure GET path — perfect.
	}

	type allowed struct {
		method  string
		funcCtx string // substring of the surrounding function name
		why     string
	}
	// Intentionally empty: the Qdrant Looter has no read-only-in-effect
	// mutating exception. Any match below is a contract violation.
	allowlist := []allowed{}

	for _, idx := range matches {
		prefix := string(src[:idx[0]])
		lastFunc := strings.LastIndex(prefix, "\nfunc ")
		if lastFunc < 0 {
			t.Fatalf("non-allowlisted mutating method at offset %d (no enclosing func)", idx[0])
		}
		funcLine := prefix[lastFunc+1:]
		if nl := strings.Index(funcLine, "\n"); nl > 0 {
			funcLine = funcLine[:nl]
		}

		method := string(src[idx[0]+1 : idx[1]-1])
		var ok bool
		for _, a := range allowlist {
			if a.method == method && strings.Contains(funcLine, a.funcCtx) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("non-allowlisted mutating method %q in func: %s (Looter contract; see sdk/action/looter.go)", method, funcLine)
		}
	}
}

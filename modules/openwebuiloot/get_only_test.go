package openwebuiloot

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestLooter_HTTPMethods enforces the Looter contract (sdk/action.Looter):
// no state-mutating requests. The Open WebUI Looter is PURE GET — both the
// anonymous posture probe (/api/config) and the authenticated upstream-key
// probe (/openai/config) are plain GETs. There is therefore NO
// POST/PUT/PATCH/DELETE/CONNECT call site.
//
// Note: Open WebUI ALSO exposes a POST /openai/config/update mutator. The
// Looter MUST NOT touch it — that is a Poisoner-class operation. The
// allowlist below is intentionally empty: any mutating-method match is a
// contract violation. If a future read-only-in-effect POST search/lookup
// is ever needed, add it here WITH a justifying comment (see the
// modules/ollamaloot/get_only_test.go precedent).
//
// Mirrors modules/mlflowloot/get_only_test.go.
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

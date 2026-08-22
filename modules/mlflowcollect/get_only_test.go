package mlflowcollect

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCollector_HTTPMethods enforces the Collector contract (sdk/action.ServiceCollector):
// no state-mutating requests. GET/HEAD is the norm; the SINGLE documented
// exception is the runs/search query, which the MLflow REST API exposes
// only via POST (it is an idempotent, side-effect-free read — a search,
// not a mutation). Any new POST/PUT/PATCH/DELETE/CONNECT call site must be
// added to the allowlist below WITH a comment explaining why it is
// read-only-in-effect, or this guard fails. PUT/PATCH/DELETE have no
// allowlist entry and can never be justified for a Collector.
//
// Mirrors modules/ollamacollect/get_only_test.go.
func TestCollector_HTTPMethods(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "collector.go"))
	if err != nil {
		t.Fatalf("read collector.go: %v", err)
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
	allowlist := []allowed{
		{
			method:  "POST",
			funcCtx: "postJSON",
			why:     "MLflow runs/search is exposed only via POST; it is a read query (search), no target state changes.",
		},
	}

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
			t.Errorf("non-allowlisted mutating method %q in func: %s (Collector contract; see sdk/action/collector.go)", method, funcLine)
		}
	}
}

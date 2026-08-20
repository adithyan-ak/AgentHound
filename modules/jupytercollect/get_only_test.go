package jupytercollect

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCollector_HTTPMethods enforces the Collector contract (sdk/action.ServiceCollector):
// no state-mutating requests. The Jupyter Collector is PURE GET — both
// probes (/api/sessions and the recursive /api/contents walk) issue
// plain GETs with no body. There is NO POST/PUT/PATCH/DELETE/CONNECT
// call site, and none is justifiable for read-only inventory.
//
// Any future addition (e.g. a POST search) MUST be added to the
// allowlist below WITH a justifying comment explaining why it is
// read-only-in-effect. PUT/PATCH/DELETE can never be justified.
//
// Mirrors modules/qdrantcollect/get_only_test.go.
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
	// Intentionally empty: the Jupyter Collector has no read-only-in-effect
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
				t.Logf("allowlisted mutating method %q in %s: %s", method, a.funcCtx, a.why)
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("non-allowlisted mutating method %q in func: %s (Collector contract; see sdk/action/collector.go)", method, funcLine)
		}
	}
}

package ollamacollect

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCollector_HTTPMethods enforces the Collector contract: GET / HEAD only,
// with a SINGLE documented exception for the embedding probe (POST
// /api/embeddings, gated behind --include-embeddings; read-only-in-effect
// on the target). Any new POST/PUT/PATCH/DELETE/CONNECT call site must be
// added to the allowlist below WITH a comment explaining why it's
// read-only-in-effect.
//
// /api/show is also a POST in the Ollama HTTP API — this is the documented
// second exception; semantically it is a "lookup with a body" since the
// body just specifies the model name and the response contains no
// state-mutating side effects.
func TestCollector_HTTPMethods(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "collector.go"))
	if err != nil {
		t.Fatalf("read collector.go: %v", err)
	}

	// Methods that imply mutation. Each occurrence must appear in the
	// allowlist below or the test fails.
	mutating := regexp.MustCompile(`"(POST|PUT|PATCH|DELETE|CONNECT)"`)
	matches := mutating.FindAllStringIndex(string(src), -1)
	if matches == nil {
		return // Pure GET path — perfect.
	}

	type allowed struct {
		method  string
		funcCtx string // substring of surrounding function name
		why     string
	}
	allowlist := []allowed{
		{
			method:  "POST",
			funcCtx: "fetchShow",
			why:     "/api/show is Ollama's lookup-with-body endpoint; semantically read-only.",
		},
		{
			method:  "POST",
			funcCtx: "probeEmbeddings",
			why:     "/api/embeddings probe; gated behind --include-embeddings; read-only-in-effect on target.",
		},
	}

	for _, idx := range matches {
		// Find the enclosing function declaration by walking backwards
		// to the most recent `func ` line.
		prefix := string(src[:idx[0]])
		lastFunc := strings.LastIndex(prefix, "\nfunc ")
		if lastFunc < 0 {
			t.Fatalf("non-allowlisted mutating method at offset %d (no enclosing func)", idx[0])
		}
		funcLine := prefix[lastFunc+1:]
		nl := strings.Index(funcLine, "\n")
		if nl > 0 {
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
			t.Errorf("non-allowlisted mutating method %q in func: %s", method, funcLine)
		}
	}
}

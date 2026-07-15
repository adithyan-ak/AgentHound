package mlflowfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
)

const mlflowBody = `{"experiments":[{"experiment_id":"0","name":"Default"}]}`

// exactlyOneMaxResultsOne parses the probe's raw query string and reports
// whether it carries exactly one max_results parameter whose value is "1".
// Stock MLflow (2.22.x+) rejects experiments/search without a valid
// max_results, so the probe contract is precise: one key, one value, "1".
// Parsing (not substring matching) rejects max_results=0, an empty value,
// duplicate keys, and unrelated keys that merely contain the substring
// (e.g. max_results_extra=1).
func exactlyOneMaxResultsOne(rawQuery string) bool {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return false
	}
	vals, ok := q["max_results"]
	if !ok || len(vals) != 1 {
		return false
	}
	return vals[0] == "1"
}

func TestFingerprint_MLflowHappy(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/2.0/mlflow/experiments/search" {
			gotQuery = r.URL.RawQuery
			// Modern MLflow rejects a search without a valid max_results.
			// Only status behavior matters here, so fail generically.
			if !exactlyOneMaxResultsOne(r.URL.RawQuery) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mlflowBody))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := f.Fingerprint(context.Background(), action.Target{
		Kind: "host", Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected Matched=true")
	}
	if res.ServiceKind != "mlflow" {
		t.Errorf("ServiceKind = %q, want mlflow", res.ServiceKind)
	}
	if !exactlyOneMaxResultsOne(gotQuery) {
		t.Errorf("probe query %q is not exactly one max_results=1 (would 400 on modern MLflow)", gotQuery)
	}

	// The probe proves only what an anonymous experiment-search establishes
	// about THIS instance: it answered without credentials. That scoped
	// observation is auth_evidence=anonymous_probe_succeeded, which is what
	// turns auth_method=none into a supported instance claim downstream
	// (common.IsConfirmedAnonymousAccess) rather than a product-wide
	// assertion that MLflow universally lacks authentication.
	if len(res.IngestData.Graph.Nodes) != 1 {
		t.Fatalf("emitted %d nodes, want 1", len(res.IngestData.Graph.Nodes))
	}
	props := res.IngestData.Graph.Nodes[0].Properties
	if got := props["auth_method"]; got != string(common.AuthNone) {
		t.Errorf("auth_method = %v, want %q", got, common.AuthNone)
	}
	if got := props["auth_evidence"]; got != common.AuthEvidenceAnonymousProbeSucceeded {
		t.Errorf("auth_evidence = %v, want %q", got, common.AuthEvidenceAnonymousProbeSucceeded)
	}
}

// TestFingerprint_MLflowMaxResultsContract locks the probe-query contract:
// exactly one max_results=1 is accepted; the substring-adjacent and
// malformed variants that a naive strings.Contains check would wrongly
// accept are all rejected.
func TestFingerprint_MLflowMaxResultsContract(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  bool
	}{
		{"exactly one max_results=1", "max_results=1", true},
		{"missing", "", false},
		{"zero", "max_results=0", false},
		{"empty value", "max_results=", false},
		{"duplicate same value", "max_results=1&max_results=1", false},
		{"duplicate different value", "max_results=1&max_results=2", false},
		{"unrelated prefixed key", "foo_max_results=1", false},
		{"unrelated suffixed key", "max_results_extra=1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exactlyOneMaxResultsOne(tc.query); got != tc.want {
				t.Errorf("exactlyOneMaxResultsOne(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

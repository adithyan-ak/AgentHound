package mlflowfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const mlflowBody = `{"experiments":[{"experiment_id":"0","name":"Default"}]}`

func TestFingerprint_MLflowHappy(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/2.0/mlflow/experiments/search" {
			gotQuery = r.URL.RawQuery
			// Stock MLflow (2.22.x+) rejects bare search without max_results.
			if !strings.Contains(r.URL.RawQuery, "max_results=") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error_code":"INVALID_PARAMETER_VALUE","message":"Missing max_results"}`))
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
	if !strings.Contains(gotQuery, "max_results=") {
		t.Errorf("probe query %q missing max_results (would 400 on modern MLflow)", gotQuery)
	}
}

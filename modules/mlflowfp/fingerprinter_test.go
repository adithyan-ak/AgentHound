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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/2.0/mlflow/experiments/search" {
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
}

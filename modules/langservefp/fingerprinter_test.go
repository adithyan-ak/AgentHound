package langservefp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const langserveDocs = `<!doctype html><html><head><title>LangServe</title></head></html>`

func TestFingerprint_LangServeHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docs" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(langserveDocs))
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
	if res.ServiceKind != "langserve" {
		t.Errorf("ServiceKind = %q, want langserve", res.ServiceKind)
	}
}

func TestFingerprint_NotLangServe(t *testing.T) {
	// vLLM-shaped body (also FastAPI under the hood) — must NOT match.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docs" {
			_, _ = w.Write([]byte(`<!doctype html><title>Swagger UI</title>`))
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
		t.Fatalf("Fingerprint err: %v", err)
	}
	if res.Matched {
		t.Error("expected no match — title doesn't contain 'LangServe'")
	}
}

package qdrantfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const qdrantBody = `{"title":"qdrant - vector search engine","version":"1.7.4"}`

func TestFingerprint_QdrantHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(qdrantBody))
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
	if res.ServiceKind != "qdrant" {
		t.Errorf("ServiceKind = %q, want qdrant", res.ServiceKind)
	}
	if res.Version != "1.7.4" {
		t.Errorf("Version = %q, want 1.7.4", res.Version)
	}
}

func TestFingerprint_NotQdrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"title":"something else","version":"1"}`))
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
		t.Error("expected no match — title doesn't contain 'qdrant'")
	}
}

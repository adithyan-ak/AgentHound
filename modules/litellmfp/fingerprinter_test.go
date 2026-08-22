package litellmfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

func TestFingerprint_LiteLLMHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/health/liveliness" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("I'm alive!"))
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
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected Matched=true")
	}
	if res.ServiceKind != "litellm" {
		t.Errorf("ServiceKind = %q, want litellm", res.ServiceKind)
	}
	if res.AuthMethod != "master_key" {
		t.Errorf("AuthMethod = %q, want master_key", res.AuthMethod)
	}
	if res.IngestData == nil || len(res.IngestData.Graph.Nodes) != 1 {
		t.Fatalf("expected 1 ingest node, got %+v", res.IngestData)
	}
	node := res.IngestData.Graph.Nodes[0]
	if len(node.Kinds) != 2 || node.Kinds[0] != "LiteLLMGateway" || node.Kinds[1] != "AIService" {
		t.Errorf("node.Kinds = %v, want [LiteLLMGateway AIService]", node.Kinds)
	}
	if got := node.Properties["service_kind"]; got != "litellm" {
		t.Errorf("properties.service_kind = %v, want litellm", got)
	}
}

func TestFingerprint_NotLiteLLM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("not a litellm response"))
	}))
	defer srv.Close()

	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint err = %v", err)
	}
	if res.Matched {
		t.Error("expected no match — wrong body content")
	}
}

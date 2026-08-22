package ollamacollect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

func TestModelfileCapturedByDefault(t *testing.T) {
	srv := ollamaStubServer(t, stubOpts{})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "AIModel" {
			continue
		}
		for _, k := range []string{"modelfile", "template", "system_prompt"} {
			if _, ok := n.Properties[k]; !ok {
				t.Errorf("AIModel.%s was not captured", k)
			}
		}
		if _, ok := n.Properties["value_hash"]; !ok {
			t.Errorf("AIModel.value_hash MUST be populated")
		}
	}
}

// TestEmbeddingProbe_DoesNotLeakPrompt asserts the embedding probe sends
// our deterministic benchmark payload and not anything operator-supplied.
// (Today there's no operator-supplied prompt — this is a regression guard
// for the day someone wires --embedding-prompt and forgets to redact it.)
func TestEmbeddingProbe_DoesNotLeakPrompt(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/tags" {
			_, _ = w.Write([]byte(tagsBody))
			return
		}
		if r.URL.Path == "/api/embeddings" {
			b, _ := io.ReadAll(r.Body)
			captured = string(b)
			_, _ = w.Write([]byte(`{"embedding":[0.1]}`))
			return
		}
		// /api/show — body matters less here.
		_, _ = w.Write([]byte(`{"modelfile":"FROM llama3"}`))
	}))
	defer srv.Close()

	l := &Collector{}
	_, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{Extras: map[string]any{"include-embeddings": true}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if captured == "" {
		t.Fatal("embedding probe was not captured")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(captured), &got); err != nil {
		t.Fatalf("embedding payload not valid JSON: %v", err)
	}
	if prompt, _ := got["prompt"].(string); prompt != "agenthound benchmark probe" {
		t.Errorf("unexpected probe prompt %q — must be the deterministic benchmark string", prompt)
	}
}

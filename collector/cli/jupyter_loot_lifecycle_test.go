package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/modules/jupyterloot"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestJupyterMaxItemsTruncationIsNotPublishedComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"a","path":"a","type":"directory"},
				{"name":"b","path":"b","type":"directory"},
				{"name":"c","path":"c","type":"directory"}
			]}`))
		default:
			_, _ = w.Write([]byte(`{"content":[]}`))
		}
	}))
	defer server.Close()

	result, err := (&jupyterloot.Looter{}).Loot(
		context.Background(),
		action.Target{Address: strings.TrimPrefix(server.URL, "http://")},
		action.LootOptions{MaxItems: 2},
	)
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	envelope := buildLootEnvelope(server.URL, "jupyter", "TRUNCATED", result)
	if envelope.Meta.Collection.State != ingest.OutcomePartial {
		t.Fatalf("collection state = %q, want partial", envelope.Meta.Collection.State)
	}
	if len(result.PartialErrors) == 0 ||
		!strings.Contains(result.PartialErrors[0], "max-items") {
		t.Fatalf("truncation diagnostic = %v", result.PartialErrors)
	}
}

func TestJupyterMaxDepthTruncationIsNotPublishedComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			_, _ = w.Write([]byte(`{"content":[{"name":"a","path":"a","type":"directory"}]}`))
		case "/api/contents/a":
			_, _ = w.Write([]byte(`{"content":[{"name":"b","path":"a/b","type":"directory"}]}`))
		default:
			_, _ = w.Write([]byte(`{"content":[]}`))
		}
	}))
	defer server.Close()

	result, err := (&jupyterloot.Looter{}).Loot(
		context.Background(),
		action.Target{Address: strings.TrimPrefix(server.URL, "http://")},
		action.LootOptions{Extras: map[string]any{"max-depth": 2}},
	)
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	envelope := buildLootEnvelope(server.URL, "jupyter", "TRUNCATED", result)
	if envelope.Meta.Collection.State != ingest.OutcomePartial {
		t.Fatalf("collection state = %q, want partial", envelope.Meta.Collection.State)
	}
	if len(result.PartialErrors) != 1 ||
		!strings.Contains(result.PartialErrors[0], "max-depth=2") {
		t.Fatalf("depth truncation diagnostic = %v", result.PartialErrors)
	}
}

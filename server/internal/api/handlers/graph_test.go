package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestHandleListNodes_NoCurrentGenerationEmptyIncomplete(t *testing.T) {
	// With a store present but no promoted generation, the read must not
	// surface staged facts: empty items, incomplete disclosure, no reader hit.
	h := &GraphHandler{gens: &fakeGenScope{}}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/graph/nodes", nil)
	h.HandleListNodes(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var p Page[ingest.Node]
	if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 0 {
		t.Errorf("expected empty items, got %d", len(p.Items))
	}
	if p.Completeness.Complete {
		t.Error("no promoted generation must not be complete")
	}
	if p.Total != nil {
		t.Error("total must be suppressed when incomplete")
	}
}

func TestParseIntParam(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		key        string
		defaultVal int
		want       int
	}{
		{name: "empty string returns default", query: "", key: "limit", defaultVal: 100, want: 100},
		{name: "valid 50", query: "limit=50", key: "limit", defaultVal: 100, want: 50},
		{name: "invalid abc returns default", query: "limit=abc", key: "limit", defaultVal: 100, want: 100},
		{name: "negative returns default", query: "limit=-1", key: "limit", defaultVal: 100, want: 100},
		{name: "zero returns default", query: "limit=0", key: "limit", defaultVal: 100, want: 100},
		{name: "exceeds max clamped", query: "limit=99999", key: "limit", defaultVal: 100, want: maxQueryLimit},
		{name: "exactly max", query: "limit=10000", key: "limit", defaultVal: 100, want: maxQueryLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/test"
			if tt.query != "" {
				url += "?" + tt.query
			}
			r := httptest.NewRequest(http.MethodGet, url, nil)
			got := parseIntParam(r, tt.key, tt.defaultVal)
			if got != tt.want {
				t.Errorf("parseIntParam() = %d, want %d", got, tt.want)
			}
		})
	}
}

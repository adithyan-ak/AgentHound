package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

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

func TestParseOffsetParamIsUncappedAndNonNegative(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  int
	}{
		{query: "offset=0", want: 0},
		{query: "offset=250000", want: 250000},
		{query: "offset=-1", want: 0},
		{query: "offset=invalid", want: 0},
	} {
		r := httptest.NewRequest(http.MethodGet, "/?"+tc.query, nil)
		if got := parseOffsetParam(r, "offset"); got != tc.want {
			t.Errorf("%s: offset = %d, want %d", tc.query, got, tc.want)
		}
	}
}

func TestWritePaginationHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writePaginationHeaders(rec, graph.PageInfo{
		Offset: 100, Limit: 100, Total: 201,
		HasMore: true, Complete: false, Revision: "rev-1",
	})

	if got := rec.Header().Get(headerTotalCount); got != "201" {
		t.Errorf("%s = %q, want 201", headerTotalCount, got)
	}
	if got := rec.Header().Get(headerHasMore); got != "true" {
		t.Errorf("%s = %q, want true", headerHasMore, got)
	}
	if got := rec.Header().Get(headerCollectionComplete); got != "false" {
		t.Errorf("%s = %q, want false", headerCollectionComplete, got)
	}
	if got := rec.Header().Get(headerRevision); got != "rev-1" {
		t.Errorf("%s = %q, want rev-1", headerRevision, got)
	}
	if got := rec.Header().Get(headerTruncated); got != "true" {
		t.Errorf("%s compatibility alias = %q, want true", headerTruncated, got)
	}
}

func TestWriteRevisionConflict(t *testing.T) {
	rec := httptest.NewRecorder()
	err := fmt.Errorf("list nodes: %w", &graph.RevisionMismatchError{
		Expected: "rev-1",
		Actual:   "rev-2",
	})
	if !writeRevisionConflict(rec, err) {
		t.Fatal("expected revision mismatch to be handled")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if got := rec.Header().Get(headerRevision); got != "rev-2" {
		t.Fatalf("%s = %q, want rev-2", headerRevision, got)
	}
	if writeRevisionConflict(httptest.NewRecorder(), errors.New("other")) {
		t.Fatal("non-revision error must not be handled as a conflict")
	}
}

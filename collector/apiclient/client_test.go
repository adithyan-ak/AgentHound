package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestHealth_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL)
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestHealth_ConnectionRefused(t *testing.T) {
	c := New("http://127.0.0.1:1")
	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
	if got := err.Error(); got != "cannot reach server at http://127.0.0.1:1: is it running?" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestIngest_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/ingest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("auth-less client must not send Authorization header, got: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing content-type: %s", r.Header.Get("Content-Type"))
		}

		var data ingest.IngestData
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if data.Meta.Collector != "mcp" {
			t.Errorf("expected collector 'mcp', got %q", data.Meta.Collector)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scan_id":"test-123","nodes_written":10,"edges_written":20,"duration":1000000000}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	result, err := c.Ingest(context.Background(), &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:   1,
			Type:      "agenthound-ingest",
			Collector: "mcp",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ScanID != "test-123" {
		t.Errorf("expected scan_id 'test-123', got %q", result.ScanID)
	}
	if result.NodesWritten != 10 {
		t.Errorf("expected 10 nodes, got %d", result.NodesWritten)
	}
	if result.EdgesWritten != 20 {
		t.Errorf("expected 20 edges, got %d", result.EdgesWritten)
	}
}

func TestIngest_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Ingest(context.Background(), &ingest.IngestData{})
	if err == nil {
		t.Fatal("expected error on 429")
	}
	expected := "rate limited by server, wait and retry"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestGetFindings_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/analysis/findings" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"abc123","severity":"critical","category":"Transitive Access","title":"Agent can reach resource","edge_kind":"CAN_REACH","source_name":"agent1","target_name":"resource1","confidence":1.0}]`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	findings, err := c.GetFindings(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "abc123" {
		t.Errorf("expected id 'abc123', got %q", findings[0].ID)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", findings[0].Severity)
	}
	if findings[0].Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", findings[0].Confidence)
	}
}

func TestGetFindings_WithSeverityFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("severity"); got != "critical" {
			t.Errorf("expected severity query param 'critical', got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	findings, err := c.GetFindings(context.Background(), "critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestGetPrebuilt_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/analysis/prebuilt/agents-shell-access" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("auth-less client must not send Authorization header, got: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"agent":"claude-desktop","tool":"run_command","host":"localhost"}]`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	rows, err := c.GetPrebuilt(context.Background(), "agents-shell-access")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0]["agent"] != "claude-desktop" {
		t.Errorf("expected agent 'claude-desktop', got %v", rows[0]["agent"])
	}
}

func TestGetPrebuilt_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.GetPrebuilt(context.Background(), "agents-shell-access")
	if err == nil {
		t.Fatal("expected error on 500")
	}
	expected := "server error (500): check server logs"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestHealth_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error on 500")
	}
	expected := "server error (500): check server logs"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestGetFindings_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.GetFindings(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on 500")
	}
	expected := "server error (500): check server logs"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestHandleError_BadRequest_WithMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"validation","message":"missing required field"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error on 400")
	}
	expected := "bad request: missing required field"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestHandleError_BadRequest_PlainText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error on 400")
	}
	expected := "bad request: not json"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestHandleError_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`forbidden`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error on 403")
	}
	expected := "unexpected status 403: forbidden"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestNew_TrailingSlash(t *testing.T) {
	c := New("http://example.com/")
	if c.baseURL != "http://example.com" {
		t.Errorf("baseURL = %q, want trailing slash stripped", c.baseURL)
	}
}

func TestIsConnectionRefused(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"dial tcp 127.0.0.1:1: connection refused", true},
		{"dial tcp: lookup nosuchhost", true},
		{"no such host found", true},
		{"timeout exceeded", false},
	}
	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			err := fmt.Errorf("%s", tt.msg)
			if got := isConnectionRefused(err); got != tt.want {
				t.Errorf("isConnectionRefused(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

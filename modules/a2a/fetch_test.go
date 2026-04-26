package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/a2a/" + name)
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return data
}

func TestFetchAgentCard_V10Path(t *testing.T) {
	body := loadFixture(t, "agent_card_v10.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	card, err := FetchAgentCard(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.Version != "v1.0" {
		t.Errorf("expected version v1.0, got %s", card.Version)
	}
	if card.CardHash == "" {
		t.Error("expected non-empty card hash")
	}
	if card.Parsed == nil {
		t.Error("expected parsed map")
	}
}

func TestFetchAgentCard_FallbackToV030(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			http.NotFound(w, r)
		case "/.well-known/agent.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	card, err := FetchAgentCard(context.Background(), srv.URL, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.Version != "v0.3.0" {
		t.Errorf("expected version v0.3.0, got %s", card.Version)
	}
}

func TestFetchAgentCard_BothPathsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, err := FetchAgentCard(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected error when both paths return 404")
	}
}

func TestFetchAgentCard_AuthHeader(t *testing.T) {
	var gotAuth string
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchAgentCard(context.Background(), srv.URL, "test-token-123", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer test-token-123" {
		t.Errorf("expected Authorization header 'Bearer test-token-123', got %q", gotAuth)
	}
}

func TestFetchAgentCard_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := FetchAgentCard(ctx, srv.URL, "", false)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestFetchAgentCard_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json{"))
	}))
	defer srv.Close()

	_, err := FetchAgentCard(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestFetchAgentCard_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchAgentCard(context.Background(), srv.URL, "", false)
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"https://example.com/.well-known/agent-card.json", "https://example.com"},
		{"https://example.com/.well-known/agent.json", "https://example.com"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"  https://example.com  ", "https://example.com"},
	}
	for _, tt := range tests {
		got := normalizeBaseURL(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

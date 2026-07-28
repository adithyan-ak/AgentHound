package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
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

	card, err := FetchAgentCard(context.Background(), srv.URL, "", false, 0)
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

	card, err := FetchAgentCard(context.Background(), srv.URL, "", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.Version != "v0.3.0" {
		t.Errorf("expected version v0.3.0, got %s", card.Version)
	}
}

func TestFetchAgentCardRetainsDuplicateKeyAsConformanceError(t *testing.T) {
	body := []byte(`{"name":"first","name":"second","signatures":[{"protected":"x","signature":"y"}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	raw, err := FetchAgentCard(context.Background(), server.URL, "", false, time.Second)
	if err != nil {
		t.Fatalf("FetchAgentCard: %v", err)
	}
	if !strings.Contains(raw.JSONValidationError, `duplicate JSON object key "name"`) {
		t.Fatalf("JSON validation error = %q", raw.JSONValidationError)
	}
	card, err := ParseAgentCard(
		context.Background(),
		raw,
		testA2AEngine(t),
		VerifyOptions{},
	)
	if err != nil {
		t.Fatalf("ParseAgentCard: %v", err)
	}
	if card.Conformant || card.SignatureStatus != SigStatusMalformed {
		t.Fatalf("duplicate-key card result = %+v", card)
	}
}

func TestFetchAgentCard_BothPathsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, err := FetchAgentCard(context.Background(), srv.URL, "", false, 0)
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

	_, err := FetchAgentCard(context.Background(), srv.URL, "test-token-123", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer test-token-123" {
		t.Errorf("expected Authorization header 'Bearer test-token-123', got %q", gotAuth)
	}
}

func TestFetchAgentCard_CredentialedSameOriginRedirect(t *testing.T) {
	body := loadFixture(t, "agent_card_v10.json")
	var redirectedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case v10Path:
			http.Redirect(w, r, "/redirected-card", http.StatusTemporaryRedirect)
		case "/redirected-card":
			redirectedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	if _, err := FetchAgentCard(
		context.Background(),
		srv.URL,
		"same-origin-token",
		false,
		time.Second,
	); err != nil {
		t.Fatalf("same-origin redirect: %v", err)
	}
	if redirectedAuth != "Bearer same-origin-token" {
		t.Fatalf("redirected Authorization = %q", redirectedAuth)
	}
}

func TestFetchAgentCard_RejectsCredentialedCrossPortRedirect(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationRequests.Add(1)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	_, err := FetchAgentCard(
		context.Background(),
		source.URL,
		"cross-port-token",
		false,
		time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "credential origin") {
		t.Fatalf("expected credential-origin redirect error, got %v", err)
	}
	if destinationRequests.Load() != 0 {
		t.Fatalf("cross-port destination received %d requests", destinationRequests.Load())
	}
}

func TestFetchAgentCard_RejectsCredentialedCrossHostRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	var source *httptest.Server
	source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == v10Path {
			redirectURL := strings.Replace(source.URL, "127.0.0.1", "localhost", 1) + "/redirected-card"
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}
		redirectedRequests.Add(1)
	}))
	t.Cleanup(source.Close)

	_, err := FetchAgentCard(
		context.Background(),
		source.URL,
		"cross-host-token",
		false,
		time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "credential origin") {
		t.Fatalf("expected credential-origin redirect error, got %v", err)
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("cross-host destination received %d requests", redirectedRequests.Load())
	}
}

func TestFetchAgentCard_RejectsHTTPSDowngradeRedirect(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationRequests.Add(1)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	_, err := FetchAgentCard(
		context.Background(),
		source.URL,
		"downgrade-token",
		true,
		time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected HTTPS downgrade error, got %v", err)
	}
	if destinationRequests.Load() != 0 {
		t.Fatalf("downgraded destination received %d requests", destinationRequests.Load())
	}
}

func TestFetchAgentCard_CredentialFreeCrossPortRedirect(t *testing.T) {
	body := loadFixture(t, "agent_card_v10.json")
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	if _, err := FetchAgentCard(
		context.Background(),
		source.URL,
		"",
		false,
		time.Second,
	); err != nil {
		t.Fatalf("credential-free cross-port redirect: %v", err)
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

	_, err := FetchAgentCard(ctx, srv.URL, "", false, 0)
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

	_, err := FetchAgentCard(context.Background(), srv.URL, "", false, 0)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestFetchAgentCard_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchAgentCard(context.Background(), srv.URL, "", false, 0)
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

// TestFetchAgentCard_TLSStrictDefault asserts that the A2A fetcher rejects a
// self-signed TLS certificate when Insecure=false (default). This guards
// against regressions where a stray InsecureSkipVerify=true silently weakens
// transport security across the codebase.
func TestFetchAgentCard_TLSStrictDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(loadFixture(t, "agent_card_v030.json"))
	}))
	defer srv.Close()

	// Insecure=false → TLS handshake should fail (unknown authority).
	_, err := FetchAgentCard(context.Background(), srv.URL, "", false, 0)
	if err == nil {
		t.Fatal("expected TLS verification error with self-signed cert; got nil")
	}
	if !strings.Contains(err.Error(), "x509") &&
		!strings.Contains(err.Error(), "certificate") &&
		!strings.Contains(err.Error(), "tls") {
		t.Errorf("expected TLS-related error, got: %v", err)
	}

	// Insecure=true → handshake should succeed.
	if _, err := FetchAgentCard(context.Background(), srv.URL, "", true, 0); err != nil {
		t.Errorf("Insecure=true against self-signed cert: unexpected error %v", err)
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

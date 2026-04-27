package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLocalToken_GeneratesNewToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")

	tok, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}

	if got := tok.Token(); len(got) == 0 {
		t.Fatal("token is empty")
	}
	if len(tok.Token()) != tokenLen*2 {
		t.Errorf("token length = %d, want %d (hex of %d bytes)", len(tok.Token()), tokenLen*2, tokenLen)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(data)) != tok.Token() {
		t.Errorf("on-disk token does not match in-memory token")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("token file perms = %o, want 0o600", perm)
		}
	}
}

func TestLocalToken_ReusesExistingToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")

	first, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("first NewLocalToken: %v", err)
	}
	second, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("second NewLocalToken: %v", err)
	}

	if first.Token() != second.Token() {
		t.Errorf("token regenerated on second load: first=%q second=%q", first.Token(), second.Token())
	}
}

func TestLocalToken_TreatsEmptyFileAsMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tok, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}
	if tok.Token() == "" {
		t.Error("empty file should trigger regeneration, got empty token")
	}
}

func TestLocalToken_MiddlewareRejectsMissingHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")
	tok, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}

	called := false
	handler := tok.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("downstream handler must not be invoked on rejected requests")
	}
	if !strings.Contains(rec.Body.String(), "UNAUTHORIZED") {
		t.Errorf("body should contain UNAUTHORIZED, got %s", rec.Body.String())
	}
}

func TestLocalToken_MiddlewareRejectsWrongToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")
	tok, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}

	handler := tok.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestLocalToken_MiddlewareRejectsMissingPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")
	tok, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}

	handler := tok.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", nil)
	// Token without "Bearer " prefix should be rejected.
	req.Header.Set("Authorization", tok.Token())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (raw token must include 'Bearer ' prefix)", rec.Code, http.StatusUnauthorized)
	}
}

func TestLocalToken_MiddlewareAllowsCorrectToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")
	tok, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}

	handler := tok.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestLocalTokenHandler_ReturnsToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.token")
	tok, err := NewLocalToken(path)
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/local-token", nil)
	rec := httptest.NewRecorder()
	LocalTokenHandler(tok)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), tok.Token()) {
		t.Errorf("body should contain token, got %s", string(body))
	}
}

func TestDefaultTokenPath_RespectsEnvOverride(t *testing.T) {
	t.Setenv("AGENTHOUND_TOKEN_PATH", "/tmp/explicit.token")
	got, err := DefaultTokenPath()
	if err != nil {
		t.Fatalf("DefaultTokenPath: %v", err)
	}
	if got != "/tmp/explicit.token" {
		t.Errorf("DefaultTokenPath = %q, want %q", got, "/tmp/explicit.token")
	}
}

func TestDefaultTokenPath_RespectsXDGConfigHome(t *testing.T) {
	t.Setenv("AGENTHOUND_TOKEN_PATH", "")
	t.Setenv("XDG_CONFIG_HOME", "/custom/config")
	got, err := DefaultTokenPath()
	if err != nil {
		t.Fatalf("DefaultTokenPath: %v", err)
	}
	want := filepath.Join("/custom/config", "agenthound", "server.token")
	if got != want {
		t.Errorf("DefaultTokenPath = %q, want %q", got, want)
	}
}

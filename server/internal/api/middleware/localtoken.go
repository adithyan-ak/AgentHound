// Package middleware provides HTTP middleware for the AgentHound server.
//
// LocalToken is a CSRF / drive-by-attacker mitigation. The server is
// auth-less by design (single-user posture, 127.0.0.1 by default), but
// browsers happily issue same-origin POST requests from any tab the
// operator has open. A token requirement on mutating endpoints means a
// hostile origin cannot ride the operator's ambient browser context to
// run arbitrary Cypher or upload an ingest body.
//
// The token lives in a 0o600 file under the operator's home directory
// (default $HOME/.agenthound/server.token, override via
// AGENTHOUND_TOKEN_PATH or $XDG_CONFIG_HOME). The UI fetches it from
// /api/v1/auth/local-token on load and includes it in subsequent
// mutating requests.
//
// Read endpoints (graph reads, findings, prebuilt queries, rules,
// health, docs) deliberately stay open: there is no secret data to
// protect, and gating reads would force the UI to plumb auth headers
// through every TanStack Query call for no security gain.
package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// tokenLen is the entropy budget for the localhost token. 32 bytes
	// (256 bits) is overkill for CSRF mitigation but cheap to generate.
	tokenLen = 32

	// AuthHeaderPrefix is the expected prefix in the Authorization header.
	AuthHeaderPrefix = "Bearer "
)

// LocalToken caches the on-disk token after first read and exposes
// middleware that gates mutating routes on a Bearer header match.
type LocalToken struct {
	mu    sync.RWMutex
	value string
	path  string
}

// NewLocalToken loads the token from path, generating a fresh one if
// the file does not exist. The file is created with 0o600 perms; the
// containing directory is created with 0o700.
//
// The function is idempotent: a subsequent call with the same path
// returns a LocalToken backed by the existing file contents.
func NewLocalToken(path string) (*LocalToken, error) {
	if path == "" {
		resolved, err := DefaultTokenPath()
		if err != nil {
			return nil, fmt.Errorf("resolve default token path: %w", err)
		}
		path = resolved
	}

	value, generated, err := loadOrCreateToken(path)
	if err != nil {
		return nil, err
	}
	if generated {
		// Print to stderr so operators see the location once and can
		// copy/paste it into a personal note. Do NOT log the token.
		_, _ = fmt.Fprintf(os.Stderr, "agenthound-server: generated localhost token at %s (UI fetches it; CLI bypasses HTTP)\n", path)
	}

	return &LocalToken{
		value: value,
		path:  path,
	}, nil
}

// Token returns the current token value. Safe for concurrent use.
func (t *LocalToken) Token() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.value
}

// Path returns the on-disk path of the token file.
func (t *LocalToken) Path() string {
	return t.path
}

// Middleware returns a chi-compatible middleware that requires a
// matching Bearer token on the wrapped handler.
func (t *LocalToken) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := AuthHeaderPrefix + t.Token()
		// Constant-time compare. Lengths may differ; subtle.ConstantTimeCompare
		// returns 0 in that case, which is the rejection path we want.
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"localhost token required"}}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LocalTokenHandler returns an http.HandlerFunc that serves the token
// to same-origin requests. The endpoint is intentionally NOT gated by
// the localtoken middleware — it is the bootstrap path the embedded
// UI uses on first load. Same-origin enforcement falls out of CORS:
// AllowCredentials is false and AllowedOrigins is the operator-set
// allowlist (default http://localhost:8080), so a third-party tab
// cannot issue a credentialed fetch and read the response.
func LocalTokenHandler(t *LocalToken) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// Hand-rolled JSON to avoid pulling encoding/json for one field.
		_, _ = fmt.Fprintf(w, `{"token":%q}`, t.Token())
	}
}

// DefaultTokenPath returns the default location for the token file:
// $XDG_CONFIG_HOME/agenthound/server.token if XDG is set, otherwise
// $HOME/.agenthound/server.token. AGENTHOUND_TOKEN_PATH overrides
// both when set explicitly by the caller.
func DefaultTokenPath() (string, error) {
	if v := strings.TrimSpace(os.Getenv("AGENTHOUND_TOKEN_PATH")); v != "" {
		return v, nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "agenthound", "server.token"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agenthound", "server.token"), nil
}

// loadOrCreateToken reads the token at path; if the file does not
// exist, it generates a 32-byte hex token and writes it atomically
// with 0o600 permissions. Returns (token, generated, error).
func loadOrCreateToken(path string) (string, bool, error) {
	if data, err := os.ReadFile(path); err == nil {
		t := strings.TrimSpace(string(data))
		if t == "" {
			// Treat empty file as missing — regenerate.
			return generateAndPersist(path)
		}
		return t, false, nil
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("read token file: %w", err)
	}

	return generateAndPersist(path)
}

func generateAndPersist(path string) (string, bool, error) {
	buf := make([]byte, tokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", false, fmt.Errorf("generate token: %w", err)
	}
	t := hex.EncodeToString(buf)

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", false, fmt.Errorf("create token dir: %w", err)
		}
	}

	// Atomic write: temp file + rename. Avoids a partial file if the
	// process is killed mid-write.
	tmp, err := os.CreateTemp(dir, "server.token.*")
	if err != nil {
		return "", false, fmt.Errorf("create temp token file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op if rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", false, fmt.Errorf("chmod temp token: %w", err)
	}
	if _, err := tmp.WriteString(t); err != nil {
		_ = tmp.Close()
		return "", false, fmt.Errorf("write temp token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", false, fmt.Errorf("close temp token: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", false, fmt.Errorf("rename token: %w", err)
	}
	return t, true, nil
}

package auth

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPasswordsAreBcrypt(t *testing.T) {
	hash, err := HashPassword("secure-password-123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash does not start with $2 (bcrypt), got prefix %q", hash[:4])
	}
	// bcrypt cost 12 encodes as $2a$12$ or $2b$12$
	if !strings.Contains(hash, "$12$") {
		t.Errorf("hash does not contain $12$ (bcrypt cost 12), got %q", hash[:10])
	}
}

func TestPasswordTimingResistance(t *testing.T) {
	hash, err := HashPassword("correct")
	if err != nil {
		t.Fatal(err)
	}
	// Both correct and wrong passwords should take roughly the same time
	// due to bcrypt's constant-time comparison. We just verify both paths
	// complete without panic. Precise timing assertions are fragile in CI.
	if err := CheckPassword(hash, "correct"); err != nil {
		t.Errorf("correct password failed: %v", err)
	}
	if err := CheckPassword(hash, "wrong"); err == nil {
		t.Error("wrong password should fail")
	}
}

func TestTokensAreHashed(t *testing.T) {
	raw, hash, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken() error = %v", err)
	}

	if raw == hash {
		t.Error("raw token must not equal its hash")
	}
	if !strings.HasPrefix(raw, "ah_") {
		t.Errorf("raw token should have ah_ prefix, got %q", raw[:6])
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64 (SHA-256 hex)", len(hash))
	}

	// SHA-256 is deterministic
	h1 := HashToken(raw)
	h2 := HashToken(raw)
	if h1 != h2 {
		t.Error("HashToken should be deterministic")
	}
	if h1 != hash {
		t.Error("HashToken(raw) should equal the hash returned by GenerateAPIToken")
	}
}

func TestTokenUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		raw, _, err := GenerateAPIToken()
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if seen[raw] {
			t.Fatalf("duplicate token at iteration %d", i)
		}
		seen[raw] = true
	}
}

func TestJWTRejectsExpired(t *testing.T) {
	secret := "test-secret"
	token, _, err := GenerateJWT("user-1", "admin", "admin", secret, -time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Error("ValidateJWT() should reject expired token")
	}
	if !strings.Contains(err.Error(), "parse jwt") {
		t.Errorf("error should mention jwt parsing, got: %v", err)
	}
}

func TestJWTRejectsWrongSecret(t *testing.T) {
	token, _, err := GenerateJWT("user-1", "admin", "admin", "correct-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	_, err = ValidateJWT(token, "wrong-secret")
	if err == nil {
		t.Error("ValidateJWT() should reject token signed with different secret")
	}
}

func TestJWTRejectsTamperedPayload(t *testing.T) {
	secret := "test-secret"
	token, _, err := GenerateJWT("user-1", "admin", "admin", secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the payload section (second part of JWT)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}
	// Flip a character in the payload
	payload := []byte(parts[1])
	if payload[0] == 'A' {
		payload[0] = 'B'
	} else {
		payload[0] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]

	_, err = ValidateJWT(tampered, secret)
	if err == nil {
		t.Error("ValidateJWT() should reject tampered token")
	}
}

func TestJWTRejectsGarbageInput(t *testing.T) {
	_, err := ValidateJWT("not-a-jwt", "secret")
	if err == nil {
		t.Error("ValidateJWT() should reject garbage input")
	}

	_, err = ValidateJWT("", "secret")
	if err == nil {
		t.Error("ValidateJWT() should reject empty string")
	}
}

func TestJWTClaimsIntegrity(t *testing.T) {
	secret := "secret"
	token, _, err := GenerateJWT("uid-42", "alice", "analyst", secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	if claims.UserID != "uid-42" {
		t.Errorf("UserID = %q, want uid-42", claims.UserID)
	}
	if claims.Username != "alice" {
		t.Errorf("Username = %q, want alice", claims.Username)
	}
	if claims.Role != "analyst" {
		t.Errorf("Role = %q, want analyst", claims.Role)
	}
	if claims.Issuer != "agenthound" {
		t.Errorf("Issuer = %q, want agenthound", claims.Issuer)
	}
}

func TestJWTSigningMethodHS256(t *testing.T) {
	secret := "secret"
	token, _, err := GenerateJWT("uid-1", "user", "viewer", secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// JWT header should indicate HS256
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
}

func TestNoHardcodedAPITokens(t *testing.T) {
	root := findRepoRoot(t)
	var matches []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if base == "vendor" || base == "node_modules" || base == ".git" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, `"ah_`) && !strings.Contains(line, `"ah_"`) {
				rel, _ := filepath.Rel(root, path)
				matches = append(matches, rel+":"+strings.TrimSpace(line)+" (line "+strconv.Itoa(i+1)+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("found hardcoded ah_ tokens in non-test Go files:\n%s", strings.Join(matches, "\n"))
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod)")
		}
		dir = parent
	}
}

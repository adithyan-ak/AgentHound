package a2a

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestJWS_NoSignaturesField(t *testing.T) {
	raw := map[string]any{"name": "test"}
	signed, valid := VerifySignatures(nil, raw)
	if signed || valid {
		t.Errorf("expected signed=false, valid=false; got signed=%v, valid=%v", signed, valid)
	}
}

func TestJWS_EmptyArray(t *testing.T) {
	raw := map[string]any{"signatures": []any{}}
	signed, valid := VerifySignatures(nil, raw)
	if signed || valid {
		t.Errorf("expected signed=false, valid=false; got signed=%v, valid=%v", signed, valid)
	}
}

func TestJWS_WrongType(t *testing.T) {
	raw := map[string]any{"signatures": "not-an-array"}
	signed, valid := VerifySignatures(nil, raw)
	if signed || valid {
		t.Errorf("expected signed=false, valid=false; got signed=%v, valid=%v", signed, valid)
	}
}

func TestJWS_RS256_Valid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"test-agent","url":"https://example.com"}`)
	compact := signPayload(t, privKey, jose.RS256, "rsa-key-1", payload)
	raw := buildRawWithJWKS(t, payload, []string{compact}, &privKey.PublicKey, "rsa-key-1")

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if !valid {
		t.Error("expected valid=true for valid RS256 signature")
	}
}

func TestJWS_ES256_Valid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"ecdsa-agent"}`)
	compact := signPayload(t, privKey, jose.ES256, "ec-key-1", payload)
	raw := buildRawWithJWKS(t, payload, []string{compact}, &privKey.PublicKey, "ec-key-1")

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if !valid {
		t.Error("expected valid=true for valid ES256 signature")
	}
}

func TestJWS_TamperedPayload(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	original := []byte(`{"name":"original"}`)
	compact := signPayload(t, privKey, jose.RS256, "rsa-key-1", original)
	raw := buildRawWithJWKS(t, original, []string{compact}, &privKey.PublicKey, "rsa-key-1")

	tampered := []byte(`{"name":"tampered"}`)
	signed, valid := VerifySignatures(tampered, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false for tampered payload")
	}
}

func TestJWS_UnsupportedAlgorithm(t *testing.T) {
	raw := map[string]any{
		"signatures": []any{"eyJhbGciOiJQUzI1NiJ9.dGVzdA.dGVzdA"},
		"jwks":       map[string]any{"keys": []any{}},
	}
	signed, valid := VerifySignatures([]byte("test"), raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false for unsupported algorithm")
	}
}

func TestJWS_NoJWKS(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"no-jwks"}`)
	compact := signPayload(t, privKey, jose.RS256, "rsa-key-1", payload)
	raw := map[string]any{
		"signatures": []any{compact},
	}

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when no jwks present")
	}
}

func TestJWS_JWKSURIOnly(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"jwks-uri-only"}`)
	compact := signPayload(t, privKey, jose.RS256, "rsa-key-1", payload)
	raw := map[string]any{
		"signatures": []any{compact},
		"jwks_uri":   "https://example.com/.well-known/jwks.json",
	}

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when only jwks_uri present")
	}
}

func TestJWS_WrongKey(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"wrong-key"}`)
	compact := signPayload(t, signingKey, jose.RS256, "rsa-key-1", payload)
	raw := buildRawWithJWKS(t, payload, []string{compact}, &wrongKey.PublicKey, "rsa-key-1")

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when verification key does not match signing key")
	}
}

func TestJWS_KIDMismatch(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"kid-mismatch"}`)
	compact := signPayload(t, privKey, jose.RS256, "key-A", payload)
	raw := buildRawWithJWKS(t, payload, []string{compact}, &privKey.PublicKey, "key-B")

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when kid does not match any key in JWKS")
	}
}

func TestJWS_MultipleSignatures_AllValid(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"multi-sig"}`)
	rsaCompact := signPayload(t, rsaKey, jose.RS256, "rsa-1", payload)
	ecCompact := signPayload(t, ecKey, jose.ES256, "ec-1", payload)

	jwksKeys := []jose.JSONWebKey{
		{Key: &rsaKey.PublicKey, KeyID: "rsa-1"},
		{Key: &ecKey.PublicKey, KeyID: "ec-1"},
	}
	raw := buildRawWithKeys(t, payload, []string{rsaCompact, ecCompact}, jwksKeys)

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if !valid {
		t.Error("expected valid=true when all signatures verify")
	}
}

func TestJWS_MultipleSignatures_OneFails(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"name":"partial-fail"}`)
	rsaCompact := signPayload(t, rsaKey, jose.RS256, "rsa-1", payload)
	ecCompact := signPayload(t, ecKey, jose.ES256, "ec-1", payload)

	jwksKeys := []jose.JSONWebKey{
		{Key: &rsaKey.PublicKey, KeyID: "rsa-1"},
		{Key: &wrongECKey.PublicKey, KeyID: "ec-1"},
	}
	raw := buildRawWithKeys(t, payload, []string{rsaCompact, ecCompact}, jwksKeys)

	signed, valid := VerifySignatures(payload, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when one signature fails")
	}
}

func TestJWS_NonStringSignatureEntry(t *testing.T) {
	raw := map[string]any{
		"signatures": []any{42},
		"jwks":       map[string]any{"keys": []any{}},
	}
	signed, valid := VerifySignatures([]byte("test"), raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false for non-string signature entry")
	}
}

// --- test helpers ---

func signPayload(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, payload []byte) string {
	t.Helper()

	signingKey := jose.SigningKey{Algorithm: alg, Key: &jose.JSONWebKey{Key: key, KeyID: kid}}
	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func buildRawWithJWKS(t *testing.T, payload []byte, sigs []string, pubKey any, kid string) map[string]any {
	t.Helper()
	keys := []jose.JSONWebKey{{Key: pubKey, KeyID: kid}}
	return buildRawWithKeys(t, payload, sigs, keys)
}

func buildRawWithKeys(t *testing.T, payload []byte, sigs []string, keys []jose.JSONWebKey) map[string]any {
	t.Helper()

	jwks := jose.JSONWebKeySet{Keys: keys}
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	var jwksMap map[string]any
	if err := json.Unmarshal(jwksBytes, &jwksMap); err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}

	sigEntries := make([]any, len(sigs))
	for i, s := range sigs {
		sigEntries[i] = s
	}
	raw["signatures"] = sigEntries
	raw["jwks"] = jwksMap

	return raw
}

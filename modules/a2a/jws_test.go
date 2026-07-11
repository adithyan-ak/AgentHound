package a2a

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

	// Any-valid semantics: one signature verifies, so the card is Valid, but
	// the status distinguishes it from a fully-verified card.
	res := VerifySignaturesCtx(context.Background(), payload, raw, VerifyOptions{})
	if !res.Signed {
		t.Error("expected signed=true")
	}
	if !res.Valid {
		t.Error("expected valid=true under any-valid semantics when at least one signature verifies")
	}
	if res.Status != SigStatusPartiallyVerified {
		t.Errorf("expected status partially_verified, got %q", res.Status)
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

func TestJWS_ObjectForm_RS256_Valid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	card := map[string]any{
		"name": "object-form-agent",
		"url":  "https://example.com/a2a",
	}
	raw := buildObjectFormCard(t, card, privKey, jose.RS256, "rsa-obj-1", &privKey.PublicKey)

	signed, valid := VerifySignatures(nil, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if !valid {
		t.Error("expected valid=true for valid object-form RS256 signature")
	}
}

func TestJWS_ObjectForm_ES256_Valid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	card := map[string]any{
		"name":         "ecdsa-object-agent",
		"capabilities": map[string]any{"streaming": true},
	}
	raw := buildObjectFormCard(t, card, privKey, jose.ES256, "ec-obj-1", &privKey.PublicKey)

	signed, valid := VerifySignatures(nil, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if !valid {
		t.Error("expected valid=true for valid object-form ES256 signature")
	}
}

func TestJWS_ObjectForm_TamperedPayload(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	card := map[string]any{"name": "original-object"}
	raw := buildObjectFormCard(t, card, privKey, jose.RS256, "rsa-obj-1", &privKey.PublicKey)

	raw["name"] = "tampered-object"

	signed, valid := VerifySignatures(nil, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when card body is tampered after signing")
	}
}

func TestJWS_ObjectForm_WrongKey(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	card := map[string]any{"name": "wrong-key-object"}
	raw := buildObjectFormCard(t, card, signingKey, jose.RS256, "rsa-obj-1", &wrongKey.PublicKey)

	signed, valid := VerifySignatures(nil, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when jwks public key does not match signer")
	}
}

func TestJWS_ObjectForm_MalformedProtected(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwksMap := jwksToMap(t, []jose.JSONWebKey{{Key: &privKey.PublicKey, KeyID: "k"}})
	raw := map[string]any{
		"name": "malformed-object",
		"signatures": []any{
			map[string]any{
				"protected": "!!!not-base64!!!",
				"signature": "also@@@bad",
			},
		},
		"jwks": jwksMap,
	}

	signed, valid := VerifySignatures(nil, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false for malformed base64 in object form")
	}
}

func TestJWS_ObjectForm_MissingFields(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwksMap := jwksToMap(t, []jose.JSONWebKey{{Key: &privKey.PublicKey, KeyID: "k"}})
	raw := map[string]any{
		"name": "missing-fields-object",
		"signatures": []any{
			map[string]any{"protected": "eyJhbGciOiJSUzI1NiJ9"},
		},
		"jwks": jwksMap,
	}

	signed, valid := VerifySignatures(nil, raw)
	if !signed {
		t.Error("expected signed=true")
	}
	if valid {
		t.Error("expected valid=false when signature member is missing")
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

// buildObjectFormCard produces a spec-shaped A2A card whose "signatures"
// member is a flattened AgentCardSignature object {protected, signature}. The
// signature is computed over the JCS-canonical card with the signatures member
// absent — identical to what canonicalSignedPayload reconstructs at verify
// time — then split into compact segments, exactly as a real issuer would
// populate the object. verifyPubKey controls which key lands in the JWKS so
// negative (wrong-key) cases can be built.
func buildObjectFormCard(t *testing.T, card map[string]any, signKey any, alg jose.SignatureAlgorithm, kid string, verifyPubKey any) map[string]any {
	t.Helper()

	// Assemble the card exactly as it will be served (inline jwks included),
	// since the spec excludes only the "signatures" member from the signed
	// content. Sign the canonical form, then attach the flattened signature.
	raw := make(map[string]any, len(card)+2)
	for k, v := range card {
		raw[k] = v
	}
	raw["jwks"] = jwksToMap(t, []jose.JSONWebKey{{Key: verifyPubKey, KeyID: kid}})

	canonical, err := canonicalSignedPayload(raw)
	if err != nil {
		t.Fatal(err)
	}

	signingKey := jose.SigningKey{Algorithm: alg, Key: &jose.JSONWebKey{Key: signKey, KeyID: kid}}
	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 compact segments, got %d", len(parts))
	}

	raw["signatures"] = []any{
		map[string]any{
			"protected": parts[0],
			"signature": parts[2],
		},
	}
	return raw
}

func jwksToMap(t *testing.T, keys []jose.JSONWebKey) map[string]any {
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
	return jwksMap
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

// signPayloadWithJKU signs payload and adds a `jku` protected header pointing
// at jwksURL, matching the A2A spec's remote-key-resolution mechanism.
func signPayloadWithJKU(t *testing.T, key any, alg jose.SignatureAlgorithm, kid, jwksURL string, payload []byte) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("jku"), jwksURL)
	signingKey := jose.SigningKey{Algorithm: alg, Key: &jose.JSONWebKey{Key: key, KeyID: kid}}
	signer, err := jose.NewSigner(signingKey, opts)
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

// jwksTestServer serves the given keys as a JWKS document over loopback HTTP.
func jwksTestServer(t *testing.T, keys []jose.JSONWebKey) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestJWS_JKUFetch_Verified(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwksTestServer(t, []jose.JSONWebKey{{Key: &privKey.PublicKey, KeyID: "jku-key-1"}})

	payload := []byte(`{"name":"jku-agent"}`)
	compact := signPayloadWithJKU(t, privKey, jose.ES256, "jku-key-1", srv.URL, payload)
	raw := map[string]any{"name": "jku-agent", "signatures": []any{compact}}

	fetcher := NewJWKSFetcher(false, 5*time.Second)
	res := VerifySignaturesCtx(context.Background(), payload, raw, VerifyOptions{Fetcher: fetcher})
	if !res.Signed {
		t.Error("expected signed=true")
	}
	if !res.Valid || res.Status != SigStatusVerified {
		t.Errorf("expected verified via jku fetch, got valid=%v status=%q", res.Valid, res.Status)
	}
}

func TestJWS_JKUOffline_Unverifiable(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwksTestServer(t, []jose.JSONWebKey{{Key: &privKey.PublicKey, KeyID: "jku-key-1"}})

	payload := []byte(`{"name":"jku-agent"}`)
	compact := signPayloadWithJKU(t, privKey, jose.ES256, "jku-key-1", srv.URL, payload)
	raw := map[string]any{"name": "jku-agent", "signatures": []any{compact}}

	// No fetcher: remote jku resolution is disabled (the --no-verify-jwks path).
	res := VerifySignaturesCtx(context.Background(), payload, raw, VerifyOptions{})
	if !res.Signed {
		t.Error("expected signed=true")
	}
	if res.Valid || res.Status != SigStatusUnverifiable {
		t.Errorf("expected unverifiable offline, got valid=%v status=%q", res.Valid, res.Status)
	}
}

func TestJWS_TrustedKeys_Verified(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"name":"trusted-agent"}`)
	compact := signPayload(t, privKey, jose.RS256, "trusted-1", payload)
	raw := map[string]any{"name": "trusted-agent", "signatures": []any{compact}}

	trusted := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &privKey.PublicKey, KeyID: "trusted-1"}}}
	res := VerifySignaturesCtx(context.Background(), payload, raw, VerifyOptions{TrustedKeys: trusted})
	if !res.Valid || res.Status != SigStatusVerified {
		t.Errorf("expected verified via trusted keys, got valid=%v status=%q", res.Valid, res.Status)
	}
}

func TestJWS_SSRFBlocked(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"name":"ssrf-agent"}`)
	// jku points at the cloud-metadata / link-local endpoint; the SSRF-safe
	// fetcher must refuse to connect, leaving the signature unverifiable.
	compact := signPayloadWithJKU(t, privKey, jose.ES256, "k1", "http://169.254.169.254/jwks.json", payload)
	raw := map[string]any{"name": "ssrf-agent", "signatures": []any{compact}}

	fetcher := NewJWKSFetcher(false, 2*time.Second)
	res := VerifySignaturesCtx(context.Background(), payload, raw, VerifyOptions{Fetcher: fetcher})
	if res.Valid || res.Status != SigStatusUnverifiable {
		t.Errorf("expected unverifiable (SSRF blocked), got valid=%v status=%q", res.Valid, res.Status)
	}
}

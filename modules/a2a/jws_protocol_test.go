package a2a

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestCanonicalSignedPayloadV1AppliesProtoJSONPresenceBeforeJCS(t *testing.T) {
	raw := validV10Card()
	raw["description"] = ""
	raw["capabilities"] = map[string]any{
		"streaming":         false,
		"pushNotifications": false,
		"extensions":        []any{},
	}
	interfaces, ok := raw["supportedInterfaces"].([]any)
	if !ok || len(interfaces) == 0 {
		t.Fatal("test card has no supported interfaces")
	}
	preferred, ok := interfaces[0].(map[string]any)
	if !ok {
		t.Fatal("test card preferred interface is not an object")
	}
	preferred["tenant"] = ""
	raw["xUnknown"] = false
	raw["signatures"] = []any{
		map[string]any{"protected": "ignored", "signature": "ignored"},
	}

	got, err := canonicalSignedPayloadV1(raw)
	if err != nil {
		t.Fatalf("canonicalSignedPayloadV1: %v", err)
	}
	want := `{"capabilities":{"pushNotifications":false,"streaming":false},"defaultInputModes":["application/json"],"defaultOutputModes":["application/json"],"description":"","name":"V1 Agent","skills":[{"description":"Summarizes input","id":"summarize","name":"Summarize","tags":["summary"]}],"supportedInterfaces":[{"protocolBinding":"JSONRPC","protocolVersion":"1.0","url":"https://agent.example/a2a"}],"version":"1.0.0","xUnknown":false}`
	if string(got) != want {
		t.Fatalf("canonical payload:\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalSignedPayloadV1UsesUTF16PropertyOrder(t *testing.T) {
	raw := validV10Card()
	raw["\ue000"] = 1
	raw["\U00010000"] = 2

	got, err := canonicalSignedPayloadV1(raw)
	if err != nil {
		t.Fatalf("canonicalSignedPayloadV1: %v", err)
	}
	if strings.Index(string(got), `"`+"\U00010000"+`"`) >
		strings.Index(string(got), `"`+"\ue000"+`"`) {
		t.Fatalf("properties are not ordered by UTF-16 code units: %s", got)
	}
}

func TestCanonicalSignedPayloadV1MaterializesMissingRequiredDefaults(t *testing.T) {
	got, err := canonicalSignedPayloadV1(map[string]any{"name": "Incomplete"})
	if err != nil {
		t.Fatalf("canonicalSignedPayloadV1: %v", err)
	}
	want := `{"capabilities":{},"defaultInputModes":[],"defaultOutputModes":[],"description":"","name":"Incomplete","skills":[],"supportedInterfaces":[],"version":""}`
	if string(got) != want {
		t.Fatalf("canonical payload:\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalSignedPayloadV1RejectsAdversarialObjectWidth(t *testing.T) {
	raw := validV10Card()
	wide := make(map[string]any, maxSignedObjectMembers+1)
	for i := 0; i <= maxSignedObjectMembers; i++ {
		wide[fmt.Sprintf("field-%03d", i)] = i
	}
	raw["xWide"] = wide

	if _, err := canonicalSignedPayloadV1(raw); err == nil ||
		!strings.Contains(err.Error(), "object members") {
		t.Fatalf("expected object-member bound error, got %v", err)
	}
}

func TestSignatureStatesAndKeyTrust(t *testing.T) {
	signingKey := mustECDSAKey(t)
	wrongKey := mustECDSAKey(t)
	trusted := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:   &signingKey.PublicKey,
		KeyID: "trusted-key",
	}}}
	wrongTrusted := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:   &wrongKey.PublicKey,
		KeyID: "trusted-key",
	}}}

	tests := []struct {
		name       string
		card       map[string]any
		opts       VerifyOptions
		wantStatus string
		wantSource string
		wantTrust  string
		wantValid  bool
	}{
		{
			name:       "malformed signature object",
			card:       withSignatures(validV10Card(), []any{"compact-signatures-are-not-agent-card-signatures"}),
			wantStatus: SigStatusMalformed,
			wantSource: SigKeySourceNone,
			wantTrust:  SigKeyTrustUnknown,
		},
		{
			name:       "protected header missing kid",
			card:       signV1Card(t, validV10Card(), signingKey, "", ""),
			opts:       VerifyOptions{TrustedKeys: trusted},
			wantStatus: SigStatusMalformed,
			wantSource: SigKeySourceNone,
			wantTrust:  SigKeyTrustUnknown,
		},
		{
			name:       "key unavailable",
			card:       signV1Card(t, validV10Card(), signingKey, "missing-key", ""),
			wantStatus: SigStatusKeyUnavailable,
			wantSource: SigKeySourceNone,
			wantTrust:  SigKeyTrustUnknown,
		},
		{
			name:       "invalid with trusted key",
			card:       signV1Card(t, validV10Card(), signingKey, "trusted-key", ""),
			opts:       VerifyOptions{TrustedKeys: wrongTrusted},
			wantStatus: SigStatusInvalid,
			wantSource: SigKeySourceTrustedStore,
			wantTrust:  SigKeyTrustTrusted,
		},
		{
			name:       "valid trusted",
			card:       signV1Card(t, validV10Card(), signingKey, "trusted-key", ""),
			opts:       VerifyOptions{TrustedKeys: trusted},
			wantStatus: SigStatusValidTrusted,
			wantSource: SigKeySourceTrustedStore,
			wantTrust:  SigKeyTrustTrusted,
			wantValid:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifySignaturesCtx(context.Background(), tt.card, "v1.0", tt.opts)
			if got.Status != tt.wantStatus ||
				got.KeySource != tt.wantSource ||
				got.KeyTrust != tt.wantTrust ||
				got.Valid != tt.wantValid {
				t.Fatalf("signature result = %+v", got)
			}
		})
	}
}

func TestSignatureRejectsDuplicateProtectedAndUnprotectedHeaders(t *testing.T) {
	signingKey := mustECDSAKey(t)
	card := signV1Card(t, validV10Card(), signingKey, "trusted-key", "")
	signatures, ok := card["signatures"].([]any)
	if !ok || len(signatures) != 1 {
		t.Fatalf("test signature fixture = %#v", card["signatures"])
	}
	signature, ok := signatures[0].(map[string]any)
	if !ok {
		t.Fatalf("test signature entry = %#v", signatures[0])
	}
	signature["header"] = map[string]any{"alg": "none"}

	got := VerifySignaturesCtx(context.Background(), card, "v1.0", VerifyOptions{
		TrustedKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:   &signingKey.PublicKey,
			KeyID: "trusted-key",
		}}},
	})
	if got.Status != SigStatusMalformed || got.Valid {
		t.Fatalf("duplicate JOSE header parameters accepted: %+v", got)
	}
}

func TestSignatureTreatsProtoJSONNullUnprotectedHeaderAsAbsent(t *testing.T) {
	signingKey := mustECDSAKey(t)
	card := signV1Card(t, validV10Card(), signingKey, "trusted-key", "")
	signature, ok := firstSignature(t, card).(map[string]any)
	if !ok {
		t.Fatalf("test signature entry = %#v", firstSignature(t, card))
	}
	signature["header"] = nil
	trusted := VerifyOptions{TrustedKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:   &signingKey.PublicKey,
		KeyID: "trusted-key",
	}}}}

	got := VerifySignaturesCtx(context.Background(), card, "v1.0", trusted)
	if !got.Valid || got.Status != SigStatusValidTrusted {
		t.Fatalf("ProtoJSON null unprotected header = %+v", got)
	}

	signature["header"] = "not-an-object"
	got = VerifySignaturesCtx(context.Background(), card, "v1.0", trusted)
	if got.Valid || got.Status != SigStatusMalformed {
		t.Fatalf("wrong-shaped unprotected header = %+v", got)
	}
}

func TestSignatureHonorsJWKAlgorithmConstraint(t *testing.T) {
	signingKey := mustECDSAKey(t)
	card := signV1Card(t, validV10Card(), signingKey, "trusted-key", "")
	got := VerifySignaturesCtx(context.Background(), card, "v1.0", VerifyOptions{
		TrustedKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &signingKey.PublicKey,
			KeyID:     "trusted-key",
			Algorithm: "ES384",
		}}},
	})
	if got.Status != SigStatusKeyUnavailable || got.Valid ||
		got.KeySource != SigKeySourceTrustedStore || got.KeyTrust != SigKeyTrustTrusted {
		t.Fatalf("JWK alg constraint ignored: %+v", got)
	}
}

func TestSignatureValidUntrustedFromHTTPSJKU(t *testing.T) {
	signingKey := mustECDSAKey(t)
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:   &signingKey.PublicKey,
		KeyID: "remote-key",
	}}}
	body, err := json.Marshal(keySet)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	card := signV1Card(t, validV10Card(), signingKey, "remote-key", server.URL)
	fetcher := &JWKSFetcher{
		client:   server.Client(),
		maxBytes: defaultJWKSMaxBytes,
		maxKeys:  defaultJWKSMaxKeys,
	}
	got := VerifySignaturesCtx(context.Background(), card, "v1.0", VerifyOptions{Fetcher: fetcher})
	if got.Status != SigStatusValidUntrusted ||
		got.KeySource != SigKeySourceJKU ||
		got.KeyTrust != SigKeyTrustUntrusted ||
		!got.Valid {
		t.Fatalf("signature result = %+v", got)
	}
}

func TestCardControlledInlineAndTopLevelKeysRemainInactive(t *testing.T) {
	signingKey := mustECDSAKey(t)
	card := signV1Card(t, validV10Card(), signingKey, "self-asserted", "")
	card["jwks"] = map[string]any{
		"keys": []any{map[string]any{
			"kty": "EC",
			"kid": "self-asserted",
		}},
	}
	card["jwks_uri"] = "https://agent.example/self-asserted.jwks"

	got := VerifySignaturesCtx(context.Background(), card, "v1.0", VerifyOptions{})
	if got.Status != SigStatusKeyUnavailable ||
		got.KeySource != SigKeySourceNone ||
		got.Valid {
		t.Fatalf("self-asserted key material became active: %+v", got)
	}
}

func TestJWKSFetcherRejectsPlainHTTPBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	_, err := NewJWKSFetcher(time.Second).Fetch(context.Background(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected HTTPS policy error, got %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("HTTP jku was requested %d times", requests.Load())
	}
}

func TestJWKSFetcherRejectsHTTPSRedirectToHTTP(t *testing.T) {
	var downgradedRequests atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		downgradedRequests.Add(1)
	}))
	t.Cleanup(httpServer.Close)
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", httpServer.URL)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(httpsServer.Close)

	fetcher := &JWKSFetcher{
		client: &http.Client{
			Transport: httpsServer.Client().Transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return validateJWKSRedirect(req, via)
			},
		},
		maxBytes: defaultJWKSMaxBytes,
		maxKeys:  defaultJWKSMaxKeys,
	}
	_, err := fetcher.Fetch(context.Background(), httpsServer.URL)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected redirect downgrade error, got %v", err)
	}
	if downgradedRequests.Load() != 0 {
		t.Fatalf("downgraded endpoint was requested %d times", downgradedRequests.Load())
	}
}

func TestV030SignaturesAreObservedWithoutV1Canonicalization(t *testing.T) {
	key := mustECDSAKey(t)
	card := signV1Card(t, validV10Card(), key, "key", "")
	got := VerifySignaturesCtx(context.Background(), card, "v0.3.0", VerifyOptions{
		TrustedKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:   &key.PublicKey,
			KeyID: "key",
		}}},
	})
	if !got.Signed || got.Valid || got.Status != SigStatusUnsupportedVersion {
		t.Fatalf("v0.3 signature result = %+v", got)
	}
}

func TestSignatureCountIsBoundedBeforeRemoteKeyResolution(t *testing.T) {
	key := mustECDSAKey(t)
	signed := signV1Card(t, validV10Card(), key, "key", "https://keys.example/jwks")
	entry := firstSignature(t, signed)
	signatures := make([]any, 17)
	for index := range signatures {
		signatures[index] = entry
	}

	result := VerifySignaturesCtx(
		context.Background(),
		withSignatures(validV10Card(), signatures),
		"v1.0",
		VerifyOptions{},
	)
	if result.Status != SigStatusMalformed || !result.Signed || result.Valid {
		t.Fatalf("over-limit signature result = %+v", result)
	}
}

func TestJKUFragmentIsRejectedWithoutRequest(t *testing.T) {
	key := mustECDSAKey(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(server.Close)

	card := signV1Card(t, validV10Card(), key, "key", server.URL+"#variant")
	result := VerifySignaturesCtx(context.Background(), card, "v1.0", VerifyOptions{
		Fetcher: &JWKSFetcher{
			client:   server.Client(),
			maxBytes: defaultJWKSMaxBytes,
			maxKeys:  defaultJWKSMaxKeys,
		},
	})
	if result.Status != SigStatusMalformed {
		t.Fatalf("fragment JKU result = %+v, want malformed", result)
	}
	if requests.Load() != 0 {
		t.Fatalf("fragment JKU requests = %d, want 0", requests.Load())
	}
}

func TestRemoteJKUSourcesAreBoundedPerCard(t *testing.T) {
	key := mustECDSAKey(t)
	var requests atomic.Int32
	fetcher := &JWKSFetcher{
		client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
				Request:    request,
			}, nil
		})},
		maxBytes: defaultJWKSMaxBytes,
		maxKeys:  defaultJWKSMaxKeys,
	}
	signatures := make([]any, 0, 8)
	for index := 0; index < 8; index++ {
		signed := signV1Card(
			t,
			validV10Card(),
			key,
			fmt.Sprintf("key-%d", index),
			fmt.Sprintf("https://keys.example/%d", index),
		)
		signatures = append(signatures, firstSignature(t, signed))
	}
	_ = VerifySignaturesCtx(
		context.Background(),
		withSignatures(validV10Card(), signatures),
		"v1.0",
		VerifyOptions{Fetcher: fetcher},
	)
	if requests.Load() > 4 {
		t.Fatalf("unique JKU requests = %d, want at most 4", requests.Load())
	}
}

func TestRemoteJKUResolutionUsesAggregateDeadline(t *testing.T) {
	key := mustECDSAKey(t)
	fetcher := &JWKSFetcher{
		client: &http.Client{
			Timeout: 80 * time.Millisecond,
			Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				select {
				case <-time.After(50 * time.Millisecond):
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
						Request:    request,
					}, nil
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
			}),
		},
		maxBytes: defaultJWKSMaxBytes,
		maxKeys:  defaultJWKSMaxKeys,
	}
	signatures := make([]any, 0, 4)
	for index := 0; index < 4; index++ {
		signed := signV1Card(
			t,
			validV10Card(),
			key,
			fmt.Sprintf("key-%d", index),
			fmt.Sprintf("https://keys.example/%d", index),
		)
		signatures = append(signatures, firstSignature(t, signed))
	}

	started := time.Now()
	_ = VerifySignaturesCtx(
		context.Background(),
		withSignatures(validV10Card(), signatures),
		"v1.0",
		VerifyOptions{Fetcher: fetcher},
	)
	if elapsed := time.Since(started); elapsed >= 160*time.Millisecond {
		t.Fatalf("signature verification took %s, want one aggregate deadline", elapsed)
	}
}

func TestRemoteJWKSFiltersExpiredAndRevokedKeys(t *testing.T) {
	signingKey := mustECDSAKey(t)
	publicJWK, err := json.Marshal(jose.JSONWebKey{Key: &signingKey.PublicKey, KeyID: "remote-key"})
	if err != nil {
		t.Fatal(err)
	}
	var keyMap map[string]any
	if err := json.Unmarshal(publicJWK, &keyMap); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name  string
		field string
		value any
	}{
		{name: "expired", field: "exp", value: time.Now().Add(-time.Hour).Unix()},
		{name: "revoked", field: "revoked", value: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			copyMap := make(map[string]any, len(keyMap)+1)
			for key, value := range keyMap {
				copyMap[key] = value
			}
			copyMap[tt.field] = tt.value
			body, err := json.Marshal(map[string]any{"keys": []any{copyMap}})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			}))
			t.Cleanup(server.Close)
			fetcher := &JWKSFetcher{
				client:   server.Client(),
				maxBytes: defaultJWKSMaxBytes,
				maxKeys:  defaultJWKSMaxKeys,
			}
			card := signV1Card(t, validV10Card(), signingKey, "remote-key", server.URL)
			got := VerifySignaturesCtx(context.Background(), card, "v1.0", VerifyOptions{Fetcher: fetcher})
			if got.Status != SigStatusKeyUnavailable || got.Valid {
				t.Fatalf("signature result = %+v", got)
			}
		})
	}
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signV1Card(
	t *testing.T,
	card map[string]any,
	key *ecdsa.PrivateKey,
	kid string,
	jku string,
) map[string]any {
	t.Helper()
	raw := make(map[string]any, len(card)+1)
	for name, value := range card {
		raw[name] = value
	}
	payload, err := canonicalSignedPayloadV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	options := &jose.SignerOptions{}
	if jku != "" {
		options.WithHeader(jose.HeaderKey("jku"), jku)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       &jose.JSONWebKey{Key: key, KeyID: kid},
	}, options)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS parts = %d", len(parts))
	}
	raw["signatures"] = []any{
		map[string]any{"protected": parts[0], "signature": parts[2]},
	}
	return raw
}

func withSignatures(card map[string]any, signatures []any) map[string]any {
	raw := make(map[string]any, len(card)+1)
	for name, value := range card {
		raw[name] = value
	}
	raw["signatures"] = signatures
	return raw
}

func firstSignature(t *testing.T, card map[string]any) any {
	t.Helper()
	signatures, ok := card["signatures"].([]any)
	if !ok || len(signatures) == 0 {
		t.Fatal("signed test card has no signatures")
	}
	return signatures[0]
}

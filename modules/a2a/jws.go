package a2a

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

var allowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// Signature verification status values emitted on A2AAgent nodes. They
// disambiguate the outcomes that the boolean signature_valid alone conflates:
// a card with no key to check against ("unverifiable") vs. a card whose
// signatures were checked and none verified ("failed").
const (
	SigStatusUnsigned          = "unsigned"
	SigStatusVerified          = "verified"
	SigStatusPartiallyVerified = "partially_verified"
	SigStatusFailed            = "failed"
	SigStatusUnverifiable      = "unverifiable"
)

const (
	defaultJWKSMaxBytes = 256 * 1024
	defaultJWKSMaxKeys  = 50
	defaultJWKSTimeout  = 10 * time.Second
)

// SignatureResult is the outcome of verifying a card's signatures.
type SignatureResult struct {
	Signed bool
	Valid  bool
	Status string
}

// VerifyOptions controls key resolution during signature verification.
type VerifyOptions struct {
	// Fetcher resolves keys from a signature's protected-header `jku` (and, as
	// a fallback, a top-level `jwks_uri`). Nil disables all network resolution
	// (offline mode); verification then relies only on inline `jwks` and
	// TrustedKeys.
	Fetcher *JWKSFetcher
	// TrustedKeys is an operator-supplied out-of-band key set (the A2A spec's
	// "trusted key store"), consulted before any network fetch.
	TrustedKeys *jose.JSONWebKeySet
}

// VerifySignatures verifies a card's signatures OFFLINE (inline `jwks` only),
// preserving the original two-value contract. New callers that want
// spec-compliant `jku` resolution should use VerifySignaturesCtx.
func VerifySignatures(cardJSON []byte, raw map[string]any) (signed bool, valid bool) {
	res := VerifySignaturesCtx(context.Background(), cardJSON, raw, VerifyOptions{})
	return res.Signed, res.Valid
}

// VerifySignaturesCtx verifies a card's JWS signatures and returns rich status.
//
// Semantics (any-valid): Valid is true when AT LEAST ONE signature verifies
// against a resolvable key. Keys are resolved, per signature, from (in order)
// the inline `jwks`, the operator's TrustedKeys, and — only when opts.Fetcher
// is set — the protected-header `jku` (A2A spec §8.4) or a top-level
// `jwks_uri`.
func VerifySignaturesCtx(ctx context.Context, cardJSON []byte, raw map[string]any, opts VerifyOptions) SignatureResult {
	sigs, ok := raw["signatures"]
	if !ok {
		return SignatureResult{Status: SigStatusUnsigned}
	}
	sigArr, ok := sigs.([]any)
	if !ok || len(sigArr) == 0 {
		return SignatureResult{Status: SigStatusUnsigned}
	}

	inline, err := extractJWKS(raw)
	if err != nil {
		slog.Warn("jws: failed to parse inline jwks", "error", err)
		inline = nil
	}

	canonical, err := canonicalSignedPayload(raw)
	if err != nil {
		slog.Warn("jws: failed to canonicalize signed payload", "error", err)
		return SignatureResult{Signed: true, Status: SigStatusFailed}
	}

	kp := &keyProvider{
		inline:  inline,
		trusted: opts.TrustedKeys,
		fetcher: opts.Fetcher,
		jwksURI: topLevelString(raw, "jwks_uri"),
	}

	var verified, failed, unresolved int
	for _, entry := range sigArr {
		switch verifyOneSignature(ctx, entry, cardJSON, canonical, kp) {
		case sigVerified:
			verified++
		case sigFailed:
			failed++
		default:
			unresolved++
		}
	}

	res := SignatureResult{Signed: true}
	switch {
	case verified == len(sigArr):
		res.Valid = true
		res.Status = SigStatusVerified
	case verified >= 1:
		res.Valid = true
		res.Status = SigStatusPartiallyVerified
	case failed >= 1:
		res.Status = SigStatusFailed
	default:
		res.Status = SigStatusUnverifiable
	}
	return res
}

type sigOutcome int

const (
	sigVerified sigOutcome = iota
	sigFailed
	sigUnresolved
)

// verifyOneSignature verifies a single signatures[] entry (compact string or
// flattened {protected,signature} object) and reports whether it verified,
// failed a resolvable-key check, or had no key to check against.
func verifyOneSignature(ctx context.Context, entry any, cardJSON, canonical []byte, kp *keyProvider) sigOutcome {
	var compact string
	objectForm := false
	switch e := entry.(type) {
	case string:
		compact = e
	case map[string]any:
		objectForm = true
		c, ok := flattenedToCompact(e, canonical)
		if !ok {
			slog.Warn("jws: object-form signature entry is malformed")
			return sigFailed
		}
		compact = c
	default:
		slog.Warn("jws: signature entry is neither string nor object")
		return sigFailed
	}

	parsed, err := jose.ParseSigned(compact, allowedAlgorithms)
	if err != nil {
		slog.Warn("jws: failed to parse signature", "error", err)
		return sigFailed
	}
	if len(parsed.Signatures) == 0 {
		slog.Warn("jws: parsed JWS has no signatures")
		return sigFailed
	}

	hdr := parsed.Signatures[0].Protected
	kid := hdr.KeyID
	jku := headerString(hdr, "jku")

	keys := kp.keysFor(ctx, kid, jku)
	if len(keys) == 0 {
		slog.Warn("jws: no key resolvable for signature", "kid", kid)
		return sigUnresolved
	}

	for i := range keys {
		verifiedPayload, verr := parsed.Verify(&keys[i])
		if verr != nil {
			continue
		}
		if !objectForm && cardJSON != nil && !bytes.Equal(verifiedPayload, cardJSON) {
			slog.Warn("jws: verified payload does not match card body")
			return sigFailed
		}
		return sigVerified
	}
	slog.Warn("jws: signature verification failed", "kid", kid)
	return sigFailed
}

// keyProvider resolves verification keys for a signature, preferring local
// sources (inline jwks, operator trusted keys) and only reaching out over the
// network (jku / jwks_uri) when a fetcher is configured.
type keyProvider struct {
	inline  *jose.JSONWebKeySet
	trusted *jose.JSONWebKeySet
	fetcher *JWKSFetcher
	jwksURI string
	cache   map[string]*jose.JSONWebKeySet
}

func (kp *keyProvider) keysFor(ctx context.Context, kid, jku string) []jose.JSONWebKey {
	var keys []jose.JSONWebKey
	add := func(set *jose.JSONWebKeySet) {
		if set == nil {
			return
		}
		if kid != "" {
			keys = append(keys, set.Key(kid)...)
		} else {
			keys = append(keys, set.Keys...)
		}
	}

	add(kp.inline)
	add(kp.trusted)
	if len(keys) > 0 || kp.fetcher == nil {
		return keys
	}

	for _, u := range []string{jku, kp.jwksURI} {
		if u == "" {
			continue
		}
		add(kp.fetchCached(ctx, u))
		if len(keys) > 0 {
			break
		}
	}
	return keys
}

func (kp *keyProvider) fetchCached(ctx context.Context, u string) *jose.JSONWebKeySet {
	if kp.cache == nil {
		kp.cache = make(map[string]*jose.JSONWebKeySet)
	}
	if set, ok := kp.cache[u]; ok {
		return set
	}
	set, err := kp.fetcher.Fetch(ctx, u)
	if err != nil {
		slog.Warn("jws: jwks fetch failed", "url", u, "error", err)
		set = nil
	}
	kp.cache[u] = set
	return set
}

// JWKSFetcher fetches a JWKS over HTTP(S) with SSRF hardening. Construct with
// NewJWKSFetcher; the zero value is not usable.
type JWKSFetcher struct {
	client   *http.Client
	maxBytes int64
	maxKeys  int
}

// NewJWKSFetcher builds an SSRF-hardened JWKS fetcher. insecure disables TLS
// certificate verification (mirrors the collector-wide --insecure). The
// dial-time Control hook rejects link-local/metadata and unspecified IPs on
// the *resolved* address — this covers redirects (which re-dial) and defeats
// DNS rebinding. Loopback and RFC1918 private ranges remain allowed so
// operators can verify internal agents.
func NewJWKSFetcher(insecure bool, timeout time.Duration) *JWKSFetcher {
	if timeout <= 0 {
		timeout = defaultJWKSTimeout
	}
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || isBlockedFetchIP(ip) {
				return fmt.Errorf("jwks fetch blocked for address %s", address)
			}
			return nil
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects (max 3)")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-http scheme %q blocked", req.URL.Scheme)
			}
			return nil
		},
	}
	return &JWKSFetcher{client: client, maxBytes: defaultJWKSMaxBytes, maxKeys: defaultJWKSMaxKeys}
}

// Fetch retrieves and parses a JWKS from rawURL. It never forwards any
// credential/Authorization header to the (card-controlled) jku host.
func (f *JWKSFetcher) Fetch(ctx context.Context, rawURL string) (*jose.JSONWebKeySet, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse jwks url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported jwks url scheme %q", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch status %d", resp.StatusCode)
	}
	if f.maxBytes > 0 && resp.ContentLength > f.maxBytes {
		return nil, fmt.Errorf("jwks response too large: %d bytes (max %d)", resp.ContentLength, f.maxBytes)
	}

	limit := f.maxBytes
	if limit <= 0 {
		limit = defaultJWKSMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	if f.maxKeys > 0 && len(set.Keys) > f.maxKeys {
		set.Keys = set.Keys[:f.maxKeys]
	}
	return &set, nil
}

// isBlockedFetchIP blocks link-local (169.254.0.0/16 incl. the 169.254.169.254
// cloud-metadata endpoint, fe80::/10), link-local multicast, and unspecified
// addresses. Loopback and RFC1918 private ranges are intentionally allowed so
// operators can verify internal agents.
func isBlockedFetchIP(ip net.IP) bool {
	return ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast()
}

// LoadJWKSFile reads a JWKS JSON file (the A2A trusted-key-store escape hatch
// backing --a2a-trusted-keys).
func LoadJWKSFile(path string) (*jose.JSONWebKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse jwks file %s: %w", path, err)
	}
	return &set, nil
}

func headerString(h jose.Header, key string) string {
	if h.ExtraHeaders == nil {
		return ""
	}
	if v, ok := h.ExtraHeaders[jose.HeaderKey(key)]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func topLevelString(raw map[string]any, key string) string {
	if v, ok := raw[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// flattenedToCompact reconstructs a compact JWS string from a flattened
// AgentCardSignature object {protected, signature}. Per the A2A spec
// (section 8.4) the signed payload is the agent card with the "signatures"
// member removed, JCS-canonicalized; it is NOT detached, so it is embedded
// base64url-encoded as the JWS payload segment.
func flattenedToCompact(entry map[string]any, canonicalPayload []byte) (string, bool) {
	protected, ok := entry["protected"].(string)
	if !ok || protected == "" {
		return "", false
	}
	signature, ok := entry["signature"].(string)
	if !ok || signature == "" {
		return "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(protected); err != nil {
		return "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(signature); err != nil {
		return "", false
	}
	payloadSeg := base64.RawURLEncoding.EncodeToString(canonicalPayload)
	return protected + "." + payloadSeg + "." + signature, true
}

// canonicalSignedPayload returns the JCS-canonicalized (RFC 8785) bytes of the
// agent card with the "signatures" member removed, matching the content the
// A2A signer signs (spec section 8.4.1). Go's encoding/json marshals map keys
// in lexicographic order with no insignificant whitespace, which satisfies
// JCS for the decoded-JSON object shapes A2A cards use; HTML escaping is
// disabled so '<', '>' and '&' are not mangled.
func canonicalSignedPayload(raw map[string]any) ([]byte, error) {
	stripped := make(map[string]any, len(raw))
	for k, v := range raw {
		if k == "signatures" {
			continue
		}
		stripped[k] = v
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(stripped); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func extractJWKS(raw map[string]any) (*jose.JSONWebKeySet, error) {
	jwksRaw, ok := raw["jwks"]
	if !ok {
		return nil, nil
	}

	jwksBytes, err := json.Marshal(jwksRaw)
	if err != nil {
		return nil, err
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		return nil, err
	}
	return &jwks, nil
}

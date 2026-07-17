package a2a

import (
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
	"strconv"
	"strings"
	"syscall"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/gowebpki/jcs"
)

var allowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

const (
	SigStatusUnsigned           = "unsigned"
	SigStatusUnsupportedVersion = "unsupported_version"
	SigStatusMalformed          = "malformed"
	SigStatusKeyUnavailable     = "key_unavailable"
	SigStatusInvalid            = "invalid"
	SigStatusValidUntrusted     = "valid_untrusted"
	SigStatusValidTrusted       = "valid_trusted"
)

const (
	SigKeySourceNone         = "none"
	SigKeySourceTrustedStore = "trusted_store"
	SigKeySourceJKU          = "jku"

	SigKeyTrustUnknown   = "unknown"
	SigKeyTrustUntrusted = "untrusted"
	SigKeyTrustTrusted   = "trusted"
)

const (
	defaultJWKSMaxBytes    = 256 * 1024
	defaultJWKSMaxKeys     = 50
	defaultJWKSTimeout     = 10 * time.Second
	maxSignaturesPerCard   = 16
	maxRemoteJWKSSources   = 4
	maxSignedCardBytes     = 1024 * 1024
	maxSignedDepth         = 32
	maxSignedObjectMembers = 128
	maxSignedTotalMembers  = 4096
)

type SignatureResult struct {
	Signed    bool
	Valid     bool
	Status    string
	KeySource string
	KeyTrust  string
}

type VerifyOptions struct {
	// Fetcher resolves only the protected JWS header's `jku`. Nil disables
	// network resolution.
	Fetcher *JWKSFetcher
	// TrustedKeys is an operator-pinned out-of-band key store. Card-controlled
	// inline and top-level key extensions are intentionally not key sources.
	TrustedKeys *jose.JSONWebKeySet
}

func VerifySignaturesCtx(
	ctx context.Context,
	raw map[string]any,
	schemaVersion string,
	opts VerifyOptions,
) SignatureResult {
	unsigned := SignatureResult{
		Status:    SigStatusUnsigned,
		KeySource: SigKeySourceNone,
		KeyTrust:  SigKeyTrustUnknown,
	}
	value, exists := raw["signatures"]
	if !exists || value == nil {
		return unsigned
	}
	signatures, ok := value.([]any)
	if !ok {
		return SignatureResult{
			Signed:    true,
			Status:    SigStatusMalformed,
			KeySource: SigKeySourceNone,
			KeyTrust:  SigKeyTrustUnknown,
		}
	}
	if len(signatures) == 0 {
		return unsigned
	}
	if len(signatures) > maxSignaturesPerCard {
		return SignatureResult{
			Signed:    true,
			Status:    SigStatusMalformed,
			KeySource: SigKeySourceNone,
			KeyTrust:  SigKeyTrustUnknown,
		}
	}
	if schemaVersion != "v1.0" {
		return SignatureResult{
			Signed:    true,
			Status:    SigStatusUnsupportedVersion,
			KeySource: SigKeySourceNone,
			KeyTrust:  SigKeyTrustUnknown,
		}
	}

	canonical, err := canonicalSignedPayloadV1(raw)
	if err != nil {
		slog.Warn("a2a jws canonicalization failed", "error", err)
		return SignatureResult{
			Signed:    true,
			Status:    SigStatusMalformed,
			KeySource: SigKeySourceNone,
			KeyTrust:  SigKeyTrustUnknown,
		}
	}

	provider := &keyProvider{
		trusted: opts.TrustedKeys,
		fetcher: opts.Fetcher,
		cache:   make(map[string]*jose.JSONWebKeySet),
	}
	verificationCtx := ctx
	if timeout := opts.Fetcher.aggregateTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		verificationCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	outcomes := make([]signatureOutcome, 0, len(signatures))
	for _, signature := range signatures {
		outcomes = append(outcomes, verifyOneSignature(verificationCtx, signature, canonical, provider))
	}
	return aggregateSignatureOutcomes(outcomes)
}

type signatureOutcome struct {
	status    string
	keySource string
	keyTrust  string
}

func verifyOneSignature(
	ctx context.Context,
	entry any,
	canonical []byte,
	provider *keyProvider,
) signatureOutcome {
	malformed := signatureOutcome{
		status:    SigStatusMalformed,
		keySource: SigKeySourceNone,
		keyTrust:  SigKeyTrustUnknown,
	}
	object, ok := entry.(map[string]any)
	if !ok {
		return malformed
	}
	protected, ok := object["protected"].(string)
	if !ok || protected == "" {
		return malformed
	}
	signature, ok := object["signature"].(string)
	if !ok || signature == "" {
		return malformed
	}
	var unprotected map[string]any
	if rawHeader, exists := object["header"]; exists && rawHeader != nil {
		var ok bool
		unprotected, ok = rawHeader.(map[string]any)
		if !ok {
			return malformed
		}
	}

	protectedBytes, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return malformed
	}
	var header map[string]any
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		return malformed
	}
	for name := range unprotected {
		if _, duplicate := header[name]; duplicate {
			return malformed
		}
	}
	algorithm, ok := header["alg"].(string)
	if !ok || !allowedAlgorithm(algorithm) {
		return malformed
	}
	kid, ok := header["kid"].(string)
	if !ok || strings.TrimSpace(kid) == "" {
		return malformed
	}
	jku := ""
	if rawJKU, exists := header["jku"]; exists {
		var ok bool
		jku, ok = rawJKU.(string)
		if !ok || strings.TrimSpace(jku) == "" {
			return malformed
		}
		jku = strings.TrimSpace(jku)
		if hasURLFragment(jku) {
			return malformed
		}
	}
	if _, err := base64.RawURLEncoding.DecodeString(signature); err != nil {
		return malformed
	}

	payloadSegment := base64.RawURLEncoding.EncodeToString(canonical)
	parsed, err := jose.ParseSigned(
		protected+"."+payloadSegment+"."+signature,
		allowedAlgorithms,
	)
	if err != nil || len(parsed.Signatures) != 1 {
		return malformed
	}

	keys, source, trust := provider.keysFor(ctx, kid, jku, algorithm)
	if len(keys) == 0 {
		return signatureOutcome{
			status:    SigStatusKeyUnavailable,
			keySource: source,
			keyTrust:  trust,
		}
	}
	for index := range keys {
		verifiedPayload, err := parsed.Verify(&keys[index])
		if err == nil && string(verifiedPayload) == string(canonical) {
			status := SigStatusValidUntrusted
			if trust == SigKeyTrustTrusted {
				status = SigStatusValidTrusted
			}
			return signatureOutcome{status: status, keySource: source, keyTrust: trust}
		}
	}
	return signatureOutcome{
		status:    SigStatusInvalid,
		keySource: source,
		keyTrust:  trust,
	}
}

func aggregateSignatureOutcomes(outcomes []signatureOutcome) SignatureResult {
	priorities := map[string]int{
		SigStatusMalformed:      1,
		SigStatusKeyUnavailable: 2,
		SigStatusInvalid:        3,
		SigStatusValidUntrusted: 4,
		SigStatusValidTrusted:   5,
	}
	selected := signatureOutcome{
		status:    SigStatusMalformed,
		keySource: SigKeySourceNone,
		keyTrust:  SigKeyTrustUnknown,
	}
	for _, outcome := range outcomes {
		if priorities[outcome.status] > priorities[selected.status] {
			selected = outcome
		}
	}
	return SignatureResult{
		Signed:    true,
		Valid:     selected.status == SigStatusValidTrusted || selected.status == SigStatusValidUntrusted,
		Status:    selected.status,
		KeySource: selected.keySource,
		KeyTrust:  selected.keyTrust,
	}
}

func allowedAlgorithm(algorithm string) bool {
	for _, allowed := range allowedAlgorithms {
		if string(allowed) == algorithm {
			return true
		}
	}
	return false
}

type keyProvider struct {
	trusted       *jose.JSONWebKeySet
	fetcher       *JWKSFetcher
	cache         map[string]*jose.JSONWebKeySet
	remoteFetches int
}

func (provider *keyProvider) keysFor(
	ctx context.Context,
	kid string,
	jku string,
	algorithm string,
) ([]jose.JSONWebKey, string, string) {
	if provider.trusted != nil {
		candidates := provider.trusted.Key(kid)
		keys := usableKeys(candidates, algorithm)
		if len(keys) > 0 {
			return keys, SigKeySourceTrustedStore, SigKeyTrustTrusted
		}
		if len(candidates) > 0 {
			return nil, SigKeySourceTrustedStore, SigKeyTrustTrusted
		}
	}
	if jku == "" {
		return nil, SigKeySourceNone, SigKeyTrustUnknown
	}
	if provider.fetcher == nil {
		return nil, SigKeySourceJKU, SigKeyTrustUntrusted
	}
	set := provider.fetchCached(ctx, jku)
	if set == nil {
		return nil, SigKeySourceJKU, SigKeyTrustUntrusted
	}
	candidates := set.Key(kid)
	return usableKeys(candidates, algorithm), SigKeySourceJKU, SigKeyTrustUntrusted
}

func (provider *keyProvider) fetchCached(
	ctx context.Context,
	rawURL string,
) *jose.JSONWebKeySet {
	if set, exists := provider.cache[rawURL]; exists {
		return set
	}
	if provider.remoteFetches >= maxRemoteJWKSSources {
		provider.cache[rawURL] = nil
		slog.Warn(
			"a2a jku fetch budget exhausted",
			"max_unique_sources",
			maxRemoteJWKSSources,
		)
		return nil
	}
	provider.remoteFetches++
	set, err := provider.fetcher.Fetch(ctx, rawURL)
	if err != nil {
		slog.Warn("a2a jku fetch failed", "url", rawURL, "error", err)
		set = nil
	}
	provider.cache[rawURL] = set
	return set
}

func usableKeys(keys []jose.JSONWebKey, algorithm string) []jose.JSONWebKey {
	result := make([]jose.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		if key.Valid() &&
			(key.Use == "" || key.Use == "sig") &&
			(key.Algorithm == "" || key.Algorithm == algorithm) {
			result = append(result, key)
		}
	}
	return result
}

type JWKSFetcher struct {
	client   *http.Client
	maxBytes int64
	maxKeys  int
	timeout  time.Duration
}

func (fetcher *JWKSFetcher) aggregateTimeout() time.Duration {
	if fetcher == nil {
		return 0
	}
	if fetcher.timeout > 0 {
		return fetcher.timeout
	}
	if fetcher.client != nil {
		return fetcher.client.Timeout
	}
	return 0
}

// NewJWKSFetcher always validates TLS certificates and server identity.
// Collector target --insecure policy never applies to card-controlled jku.
func NewJWKSFetcher(timeout time.Duration) *JWKSFetcher {
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
				return fmt.Errorf("jku fetch blocked for address %s", address)
			}
			return nil
		},
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &JWKSFetcher{
		client: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: validateJWKSRedirect,
		},
		maxBytes: defaultJWKSMaxBytes,
		maxKeys:  defaultJWKSMaxKeys,
		timeout:  timeout,
	}
}

func validateJWKSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return fmt.Errorf("too many jku redirects (max 3)")
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("jku redirects must remain https")
	}
	return nil
}

func (fetcher *JWKSFetcher) Fetch(
	ctx context.Context,
	rawURL string,
) (*jose.JSONWebKeySet, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse jku: %w", err)
	}
	if hasURLFragment(rawURL) {
		return nil, fmt.Errorf("jku must not contain a fragment")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("jku must use https")
	}
	if parsed.Hostname() == "" || parsed.User != nil {
		return nil, fmt.Errorf("jku must have a valid authority without userinfo")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := fetcher.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch jku: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jku fetch status %d", response.StatusCode)
	}

	limit := fetcher.maxBytes
	if limit <= 0 {
		limit = defaultJWKSMaxBytes
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf(
			"jku response too large: %d bytes (max %d)",
			response.ContentLength,
			limit,
		)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("jku response exceeds %d bytes", limit)
	}
	return parseJWKS(body, fetcher.maxKeys, time.Now())
}

func hasURLFragment(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err != nil || parsed.Fragment != "" || strings.Contains(rawURL, "#")
}

func parseJWKS(
	data []byte,
	maxKeys int,
	now time.Time,
) (*jose.JSONWebKeySet, error) {
	var envelope struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	result := &jose.JSONWebKeySet{}
	for _, rawKey := range envelope.Keys {
		if keyMetadataDisables(rawKey, now) {
			continue
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(rawKey, &key); err != nil {
			return nil, fmt.Errorf("parse jwk: %w", err)
		}
		if key.Valid() && (key.Use == "" || key.Use == "sig") {
			result.Keys = append(result.Keys, key)
		}
		if maxKeys > 0 && len(result.Keys) >= maxKeys {
			break
		}
	}
	return result, nil
}

func keyMetadataDisables(data []byte, now time.Time) bool {
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(data, &metadata); err != nil {
		return true
	}
	if raw, exists := metadata["revoked"]; exists {
		var revoked bool
		if json.Unmarshal(raw, &revoked) == nil && revoked {
			return true
		}
	}
	if raw, exists := metadata["status"]; exists {
		var status string
		if json.Unmarshal(raw, &status) == nil && strings.EqualFold(status, "revoked") {
			return true
		}
	}
	if raw, exists := metadata["exp"]; exists {
		if expiry, ok := parseKeyExpiry(raw); ok && !now.Before(expiry) {
			return true
		}
	}
	if raw, exists := metadata["key_ops"]; exists {
		var operations []string
		if json.Unmarshal(raw, &operations) == nil {
			for _, operation := range operations {
				if operation == "verify" {
					return false
				}
			}
			return true
		}
	}
	return false
}

func parseKeyExpiry(raw json.RawMessage) (time.Time, bool) {
	var numeric json.Number
	if err := json.Unmarshal(raw, &numeric); err == nil {
		seconds, err := strconv.ParseInt(numeric.String(), 10, 64)
		if err == nil {
			return time.Unix(seconds, 0), true
		}
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return time.Time{}, false
	}
	if seconds, err := strconv.ParseInt(text, 10, 64); err == nil {
		return time.Unix(seconds, 0), true
	}
	parsed, err := time.Parse(time.RFC3339, text)
	return parsed, err == nil
}

func isBlockedFetchIP(ip net.IP) bool {
	return ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast()
}

func LoadJWKSFile(path string) (*jose.JSONWebKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	set, err := parseJWKS(data, defaultJWKSMaxKeys, time.Now())
	if err != nil {
		return nil, fmt.Errorf("parse jwks file %s: %w", path, err)
	}
	return set, nil
}

type protoMessageSchema map[string]protoFieldSchema

type protoFieldSchema struct {
	required       bool
	optional       bool
	message        protoMessageSchema
	repeated       protoMessageSchema
	repeatedScalar bool
	mapValue       protoMessageSchema
	isMap          bool
}

var v1AgentCardSchema = protoMessageSchema{
	"name":        {required: true},
	"description": {required: true},
	"supportedInterfaces": {required: true, repeated: protoMessageSchema{
		"url":             {required: true},
		"protocolBinding": {required: true},
		"tenant":          {},
		"protocolVersion": {required: true},
	}},
	"provider": {message: protoMessageSchema{
		"url":          {required: true},
		"organization": {required: true},
	}},
	"version":          {required: true},
	"documentationUrl": {optional: true},
	"capabilities": {required: true, message: protoMessageSchema{
		"streaming":         {optional: true},
		"pushNotifications": {optional: true},
		"extensions": {repeated: protoMessageSchema{
			"uri":         {},
			"description": {},
			"required":    {},
			"params":      {message: protoMessageSchema{}},
		}},
		"extendedAgentCard": {optional: true},
	}},
	"securitySchemes": {isMap: true, mapValue: securitySchemeSchema()},
	"securityRequirements": {
		repeated: securityRequirementSchema(),
	},
	"defaultInputModes":  {required: true, repeatedScalar: true},
	"defaultOutputModes": {required: true, repeatedScalar: true},
	"skills": {required: true, repeated: protoMessageSchema{
		"id":          {required: true},
		"name":        {required: true},
		"description": {required: true},
		"tags":        {required: true, repeatedScalar: true},
		"examples":    {},
		"inputModes":  {},
		"outputModes": {},
		"securityRequirements": {
			repeated: securityRequirementSchema(),
		},
	}},
	"iconUrl": {optional: true},
}

func securityRequirementSchema() protoMessageSchema {
	return protoMessageSchema{
		"schemes": {
			isMap: true,
			mapValue: protoMessageSchema{
				"list": {},
			},
		},
	}
}

func securitySchemeSchema() protoMessageSchema {
	scalarDescription := protoMessageSchema{"description": {}}
	return protoMessageSchema{
		"apiKeySecurityScheme": {message: protoMessageSchema{
			"description": {},
			"location":    {required: true},
			"name":        {required: true},
		}},
		"httpAuthSecurityScheme": {message: protoMessageSchema{
			"description":  {},
			"scheme":       {required: true},
			"bearerFormat": {},
		}},
		"oauth2SecurityScheme": {message: protoMessageSchema{
			"description":       {},
			"flows":             {required: true, message: oauthFlowsSchema()},
			"oauth2MetadataUrl": {},
		}},
		"openIdConnectSecurityScheme": {message: protoMessageSchema{
			"description":      {},
			"openIdConnectUrl": {required: true},
		}},
		"mtlsSecurityScheme": {message: scalarDescription},
	}
}

func oauthFlowsSchema() protoMessageSchema {
	scopes := protoFieldSchema{required: true, isMap: true}
	return protoMessageSchema{
		"authorizationCode": {message: protoMessageSchema{
			"authorizationUrl": {required: true},
			"tokenUrl":         {required: true},
			"refreshUrl":       {},
			"scopes":           scopes,
			"pkceRequired":     {},
		}},
		"clientCredentials": {message: protoMessageSchema{
			"tokenUrl":   {required: true},
			"refreshUrl": {},
			"scopes":     scopes,
		}},
		"implicit": {message: protoMessageSchema{
			"authorizationUrl": {},
			"refreshUrl":       {},
			"scopes":           {isMap: true},
		}},
		"password": {message: protoMessageSchema{
			"tokenUrl":   {},
			"refreshUrl": {},
			"scopes":     {isMap: true},
		}},
		"deviceCode": {message: protoMessageSchema{
			"deviceAuthorizationUrl": {required: true},
			"tokenUrl":               {required: true},
			"refreshUrl":             {},
			"scopes":                 scopes,
		}},
	}
}

type normalizationLimits struct {
	members int
}

func canonicalSignedPayloadV1(raw map[string]any) ([]byte, error) {
	preflight, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	if len(preflight) > maxSignedCardBytes {
		return nil, fmt.Errorf("signed card exceeds %d bytes", maxSignedCardBytes)
	}
	normalized, err := normalizeProtoMessage(
		raw,
		v1AgentCardSchema,
		0,
		&normalizationLimits{},
		true,
	)
	if err != nil {
		return nil, err
	}
	serialized, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	if len(serialized) > maxSignedCardBytes {
		return nil, fmt.Errorf("normalized signed card exceeds %d bytes", maxSignedCardBytes)
	}
	return jcs.Transform(serialized)
}

func normalizeProtoMessage(
	raw map[string]any,
	schema protoMessageSchema,
	depth int,
	limits *normalizationLimits,
	root bool,
) (map[string]any, error) {
	if depth > maxSignedDepth {
		return nil, fmt.Errorf("signed card exceeds maximum depth %d", maxSignedDepth)
	}
	if len(raw) > maxSignedObjectMembers {
		return nil, fmt.Errorf(
			"signed card object members %d exceed maximum %d",
			len(raw),
			maxSignedObjectMembers,
		)
	}
	limits.members += len(raw)
	if limits.members > maxSignedTotalMembers {
		return nil, fmt.Errorf(
			"signed card total members exceed maximum %d",
			maxSignedTotalMembers,
		)
	}

	result := make(map[string]any, len(raw))
	for name, value := range raw {
		if root && name == "signatures" {
			continue
		}
		field, known := schema[name]
		normalized, err := normalizeProtoValue(value, field, known, depth+1, limits)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if known && !field.required && !field.optional &&
			protoDefaultValue(normalized, field) {
			continue
		}
		result[name] = normalized
	}
	for name, field := range schema {
		if !field.required {
			continue
		}
		if _, exists := raw[name]; exists {
			continue
		}
		result[name] = requiredProtoDefault(field)
	}
	return result, nil
}

func requiredProtoDefault(field protoFieldSchema) any {
	switch {
	case field.message != nil:
		return map[string]any{}
	case field.repeated != nil || field.repeatedScalar:
		return []any{}
	case field.isMap:
		return map[string]any{}
	default:
		// Every required scalar reachable from AgentCard in v1.0.1 is a
		// string. No numeric/boolean required scalar needs a distinct default.
		return ""
	}
}

func normalizeProtoValue(
	value any,
	field protoFieldSchema,
	known bool,
	depth int,
	limits *normalizationLimits,
) (any, error) {
	if object, ok := value.(map[string]any); ok {
		switch {
		case known && field.message != nil:
			return normalizeProtoMessage(object, field.message, depth, limits, false)
		case known && field.isMap:
			return normalizeProtoMap(object, field.mapValue, depth, limits)
		default:
			return normalizeProtoMessage(object, nil, depth, limits, false)
		}
	}
	if array, ok := value.([]any); ok {
		result := make([]any, 0, len(array))
		for index, item := range array {
			if object, ok := item.(map[string]any); ok {
				itemSchema := protoMessageSchema(nil)
				if known {
					itemSchema = field.repeated
				}
				normalized, err := normalizeProtoMessage(
					object,
					itemSchema,
					depth,
					limits,
					false,
				)
				if err != nil {
					return nil, fmt.Errorf("[%d]: %w", index, err)
				}
				result = append(result, normalized)
				continue
			}
			result = append(result, item)
		}
		return result, nil
	}
	return value, nil
}

func normalizeProtoMap(
	raw map[string]any,
	valueSchema protoMessageSchema,
	depth int,
	limits *normalizationLimits,
) (map[string]any, error) {
	if len(raw) > maxSignedObjectMembers {
		return nil, fmt.Errorf(
			"signed card object members %d exceed maximum %d",
			len(raw),
			maxSignedObjectMembers,
		)
	}
	limits.members += len(raw)
	if limits.members > maxSignedTotalMembers {
		return nil, fmt.Errorf(
			"signed card total members exceed maximum %d",
			maxSignedTotalMembers,
		)
	}
	result := make(map[string]any, len(raw))
	for name, value := range raw {
		if object, ok := value.(map[string]any); ok && valueSchema != nil {
			normalized, err := normalizeProtoMessage(
				object,
				valueSchema,
				depth,
				limits,
				false,
			)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			result[name] = normalized
		} else {
			normalized, err := normalizeProtoValue(
				value,
				protoFieldSchema{},
				false,
				depth+1,
				limits,
			)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			result[name] = normalized
		}
	}
	return result, nil
}

func protoDefaultValue(value any, field protoFieldSchema) bool {
	if field.message != nil {
		return false
	}
	switch typed := value.(type) {
	case nil:
		return true
	case bool:
		return !typed
	case string:
		return typed == ""
	case float64:
		return typed == 0
	case float32:
		return typed == 0
	case int:
		return typed == 0
	case int32:
		return typed == 0
	case int64:
		return typed == 0
	case uint:
		return typed == 0
	case uint32:
		return typed == 0
	case uint64:
		return typed == 0
	case []any:
		return len(typed) == 0
	case map[string]any:
		return field.isMap && len(typed) == 0
	default:
		return false
	}
}

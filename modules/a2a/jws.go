package a2a

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"

	jose "github.com/go-jose/go-jose/v4"
)

var allowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

func VerifySignatures(cardJSON []byte, raw map[string]any) (signed bool, valid bool) {
	sigs, ok := raw["signatures"]
	if !ok {
		return false, false
	}

	sigArr, ok := sigs.([]any)
	if !ok || len(sigArr) == 0 {
		return false, false
	}

	jwks, err := extractJWKS(raw)
	if err != nil {
		slog.Warn("jws: failed to parse inline jwks", "error", err)
		return true, false
	}
	if jwks == nil {
		if _, hasURI := raw["jwks_uri"]; hasURI {
			slog.Warn("jws: jwks_uri present but inline jwks missing; skipping verification (fetch not supported here)")
		} else {
			slog.Warn("jws: no jwks or jwks_uri found; cannot verify signatures")
		}
		return true, false
	}

	canonical, err := canonicalSignedPayload(raw)
	if err != nil {
		slog.Warn("jws: failed to canonicalize signed payload", "error", err)
		return true, false
	}

	for i, entry := range sigArr {
		var compact string
		objectForm := false
		switch e := entry.(type) {
		case string:
			compact = e
		case map[string]any:
			objectForm = true
			compact, ok = flattenedToCompact(e, canonical)
			if !ok {
				slog.Warn("jws: object-form signature entry is malformed", "index", i)
				return true, false
			}
		default:
			slog.Warn("jws: signature entry is neither string nor object", "index", i)
			return true, false
		}

		jws, err := jose.ParseSigned(compact, allowedAlgorithms)
		if err != nil {
			slog.Warn("jws: failed to parse signature", "index", i, "error", err)
			return true, false
		}

		if len(jws.Signatures) == 0 {
			slog.Warn("jws: parsed JWS has no signatures", "index", i)
			return true, false
		}

		kid := jws.Signatures[0].Protected.KeyID
		keys := jwks.Key(kid)
		if len(keys) == 0 {
			slog.Warn("jws: no key found for kid", "kid", kid, "index", i)
			return true, false
		}

		verified := false
		for _, key := range keys {
			verifiedPayload, err := jws.Verify(&key)
			if err == nil {
				if !objectForm && cardJSON != nil && !bytes.Equal(verifiedPayload, cardJSON) {
					slog.Warn("jws: verified payload does not match card body", "index", i)
					return true, false
				}
				verified = true
				break
			}
		}
		if !verified {
			slog.Warn("jws: signature verification failed", "kid", kid, "index", i)
			return true, false
		}
	}

	return true, true
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

package a2a

import (
	"bytes"
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

	for i, entry := range sigArr {
		compact, ok := entry.(string)
		if !ok {
			slog.Warn("jws: signature entry is not a string", "index", i)
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
				if cardJSON != nil && !bytes.Equal(verifiedPayload, cardJSON) {
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

// Package middleware provides HTTP middleware for the AgentHound server.
//
// OriginGuard is the CSRF defense on mutating endpoints. The server is
// single-user and binds 127.0.0.1:8080 by default, so the threat is a
// malicious tab in the operator's browser auto-submitting a cross-origin
// POST to a localhost endpoint — not a remote network attacker.
//
// Posture (per Fetch spec §3.1, all modern browsers attach Origin on
// every cross-origin POST and on same-origin non-GET requests):
//
//   - Empty / missing Origin header -> ALLOW. This is a non-browser
//     caller (curl, agenthound CLI, cron pipeline). The threat model
//     treats "process running on the user's machine" as inside the
//     trust boundary; if an attacker has shell access they can do
//     worse than POST to /ingest.
//   - Origin == "null"              -> REJECT. Sandboxed iframes,
//     data: / file: URLs all serialize to "null"; an attacker could
//     load AgentHound's UI inside a sandboxed iframe on evil.com.
//   - Origin in allowlist            -> ALLOW.
//   - Anything else                  -> 403.
//
// The allowlist is shared with CORS (AGENTHOUND_CORS_ORIGINS, default
// http://localhost:8080 and http://127.0.0.1:8080), so configuration is
// one env var, not two. Same-origin UI requests carry their own Origin
// per Fetch spec; cross-origin browser CSRF cannot suppress Origin.
package middleware

import (
	"net/http"
	"strings"
)

// OriginGuard returns chi-compatible middleware that rejects browser
// requests from origins not in the allowlist. allowed should be the
// CORS allowlist; values are normalized (lowercased, trailing slash
// stripped) so operators who paste "http://localhost:8080/" still get
// a match.
func OriginGuard(allowed []string) func(http.Handler) http.Handler {
	set := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		if n := normalizeOrigin(o); n != "" {
			set[n] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Header.Values distinguishes nil (header absent) from
			// [""] (header present but empty). Fetch never emits an
			// empty value, but a misbehaving proxy might — treat as
			// absent.
			vals := r.Header.Values("Origin")
			if len(vals) == 0 || strings.TrimSpace(vals[0]) == "" {
				next.ServeHTTP(w, r) // non-browser caller
				return
			}
			origin := normalizeOrigin(vals[0])
			if origin == "null" {
				forbidOrigin(w, "origin 'null' rejected")
				return
			}
			if _, ok := set[origin]; !ok {
				forbidOrigin(w, "origin not allowed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// normalizeOrigin lowercases and trims trailing slashes. Per RFC 6454
// §4, scheme and host are case-insensitive; the port is preserved
// verbatim. An Origin has no path component, so lowercasing the whole
// string is safe. TrimRight strips any run of trailing slashes,
// matching the most lenient operator paste (`http://localhost:8080///`).
func normalizeOrigin(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "/")
	return strings.ToLower(s)
}

func forbidOrigin(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":{"code":"FORBIDDEN","message":"` + msg + `"}}`))
}

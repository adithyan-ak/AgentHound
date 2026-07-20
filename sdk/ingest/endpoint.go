package ingest

import (
	"net/url"
	"strings"
)

const InvalidHTTPEndpointDisplay = "<invalid-http-endpoint>"

// SanitizedHTTPEndpoint is a public, non-executable representation of an HTTP
// endpoint. Display is safe for graph properties, collection outcomes, and
// diagnostics: URL userinfo, query, and fragment bytes are never retained.
// Valid is false when the input is not an absolute HTTP(S) URL with an
// authority; in that case Display is a fixed placeholder rather than any part
// of the potentially sensitive input.
type SanitizedHTTPEndpoint struct {
	Display          string
	Valid            bool
	UserinfoRedacted bool
	QueryRedacted    bool
	FragmentRedacted bool
}

// Redacted reports whether any input bytes were omitted from Display. Invalid
// endpoints are fully omitted and therefore always count as redacted.
func (endpoint SanitizedHTTPEndpoint) Redacted() bool {
	return !endpoint.Valid || endpoint.UserinfoRedacted ||
		endpoint.QueryRedacted || endpoint.FragmentRedacted
}

// SanitizeHTTPEndpoint removes credential-bearing URL components from a value
// intended only for display or persistence. It deliberately does not return an
// error because url.Parse errors can quote the raw URL and leak credentials.
// Collectors must continue using the untouched input in memory for transport
// and v1 HTTP identity; only the returned Display belongs in artifacts.
func SanitizeHTTPEndpoint(raw string) SanitizedHTTPEndpoint {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() ||
		(strings.ToLower(parsed.Scheme) != "http" && strings.ToLower(parsed.Scheme) != "https") ||
		parsed.Host == "" || parsed.Hostname() == "" {
		return SanitizedHTTPEndpoint{
			Display: InvalidHTTPEndpointDisplay,
			Valid:   false,
		}
	}

	sanitized := *parsed
	result := SanitizedHTTPEndpoint{
		Valid:            true,
		UserinfoRedacted: parsed.User != nil,
		QueryRedacted:    parsed.RawQuery != "" || parsed.ForceQuery,
		FragmentRedacted: parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(raw, "#"),
	}
	sanitized.User = nil
	sanitized.RawQuery = ""
	sanitized.ForceQuery = false
	sanitized.Fragment = ""
	sanitized.RawFragment = ""
	result.Display = sanitized.String()
	return result
}

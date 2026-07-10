package openwebuiloot

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// canonicalizeBackendURL normalizes a captured backend URL to
// "scheme://host:port" (no path, no query). Returns empty when the
// input is unparseable so the caller skips the emission rather than
// producing a junk endpoint.
//
// Open WebUI's OLLAMA_BASE_URLS entries may lack a scheme (Open WebUI
// stores host:port in some flows) — we default to http:// so url.Parse
// succeeds and downstream ComputeNodeID("OllamaInstance", ...) matches
// what ollamafp emits for the same host.
//
// This helper was previously in modules/openwebuifp/fingerprinter.go
// (canonicalizeBackend) but is now owned by the Looter since the
// fingerprinter no longer emits the EXPOSES edge — the Looter reads
// OLLAMA_BASE_URLS from the admin-gated /ollama/config endpoint and
// canonicalizes each entry before emitting placeholder OllamaInstance
// nodes.
func canonicalizeBackendURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		// Default Ollama port — matches what ollamafp uses for objectid.
		port = "11434"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

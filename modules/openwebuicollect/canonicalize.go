package openwebuicollect

import "github.com/adithyan-ak/agenthound/sdk/action"

// canonicalizeBackendURL applies the same endpoint identity used by Ollama's
// direct collectors. URL-shaped values retain their explicit port and base
// path; the Ollama default applies only to host-shaped values.
//
// Open WebUI's OLLAMA_BASE_URLS entries may lack a scheme (Open WebUI
// stores host:port in some flows) — we default to http:// so url.Parse
// succeeds and downstream ComputeNodeID("OllamaInstance", ...) matches
// what ollamafp emits for the same host.
//
// This helper was previously in modules/openwebuifp/fingerprinter.go
// (canonicalizeBackend) but is now owned by the Collector since the
// fingerprinter no longer emits the EXPOSES edge — the Collector reads
// OLLAMA_BASE_URLS from the admin-gated /ollama/config endpoint and
// canonicalizes each entry before emitting placeholder OllamaInstance
// nodes.
func canonicalizeBackendURL(raw string) string {
	canonical := action.EndpointBaseURL(
		action.Target{Kind: "url", Address: raw}, 11434, "http",
	)
	if _, err := action.CanonicalEndpointIdentity(
		action.Target{Kind: "url", Address: canonical}, 11434, "http",
	); err != nil {
		return ""
	}
	return canonical
}

func canonicalizeQdrantBackendURL(raw string) string {
	canonical, err := action.CanonicalEndpointIdentity(
		action.Target{Kind: "url", Address: raw}, 6333, "http",
	)
	if err != nil {
		return ""
	}
	return canonical
}

package common

import "strings"

// A2A well-known agent-card paths. v0.3.0+ serves the card at
// agent-card.json; legacy deployments serve agent.json.
const (
	A2AWellKnownCardPath   = "/.well-known/agent-card.json"
	A2AWellKnownLegacyPath = "/.well-known/agent.json"
)

// NormalizeA2ABaseURL reduces an A2A endpoint or agent-card URL to the
// canonical base URL used to derive the deterministic A2AAgent node ID.
// It is the single source of truth for both the protoscan discovery
// emitter and the full a2a collector so the two collectors compute
// identical IDs at the merge point.
//
// Normalization: trim whitespace, inject an https:// scheme when none is
// present, strip a trailing slash, then strip a well-known agent-card
// suffix. The scheme injection only affects scheme-less inputs (e.g. an
// agent-card "url" field that omits the scheme); fully-qualified inputs
// pass through unchanged.
func NormalizeA2ABaseURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	rawURL = strings.TrimRight(rawURL, "/")
	rawURL = strings.TrimSuffix(rawURL, A2AWellKnownCardPath)
	rawURL = strings.TrimSuffix(rawURL, A2AWellKnownLegacyPath)
	return rawURL
}

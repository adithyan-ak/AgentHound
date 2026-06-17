package action

import "testing"

func TestEndpointBaseURLPreservesURLScheme(t *testing.T) {
	got := EndpointBaseURL(Target{Address: "https://example.com:443"}, 4000, "http")
	if got != "https://example.com:443" {
		t.Fatalf("EndpointBaseURL = %q, want https://example.com:443", got)
	}
}

func TestEndpointBaseURLUsesMetadataSchemeOverride(t *testing.T) {
	got := EndpointBaseURL(Target{
		Address: "https://example.com:443",
		Meta:    map[string]string{"scheme": "http"},
	}, 4000, "http")
	if got != "http://example.com:443" {
		t.Fatalf("EndpointBaseURL = %q, want http://example.com:443", got)
	}
}

func TestEndpointBaseURLUsesExplicitURLOverride(t *testing.T) {
	got := EndpointBaseURL(Target{
		Address: "example.com:1234",
		Meta:    map[string]string{"url": "https://override.example/mcp/"},
	}, 4000, "http")
	if got != "https://override.example/mcp" {
		t.Fatalf("EndpointBaseURL = %q, want explicit override", got)
	}
}

package campaign

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type stubScenario struct{ id string }

func (s stubScenario) ID() string          { return s.id }
func (s stubScenario) Version() int        { return 1 }
func (s stubScenario) Description() string { return "stub" }
func (s stubScenario) Run(_ context.Context, _ RunInput) (*RunResult, error) {
	return &RunResult{}, nil
}

func TestRegistryRegisterGetList(t *testing.T) {
	// Registration mutates package state; use unique IDs to stay isolated.
	Register(stubScenario{id: "zeta-scenario"})
	Register(stubScenario{id: "alpha-scenario"})

	if _, ok := Get("zeta-scenario"); !ok {
		t.Fatal("registered scenario not found")
	}
	if _, ok := Get("missing-scenario"); ok {
		t.Fatal("unregistered scenario should not be found")
	}

	list := List()
	// List is sorted; alpha must precede zeta among our two registrations.
	var alphaIdx, zetaIdx = -1, -1
	for i, s := range list {
		switch s.ID() {
		case "alpha-scenario":
			alphaIdx = i
		case "zeta-scenario":
			zetaIdx = i
		}
	}
	if alphaIdx == -1 || zetaIdx == -1 || alphaIdx > zetaIdx {
		t.Fatalf("List not sorted: alpha=%d zeta=%d", alphaIdx, zetaIdx)
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	Register(stubScenario{id: "dup-scenario"})
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration must panic")
		}
	}()
	Register(stubScenario{id: "dup-scenario"})
}

func TestRegistryEmptyIDPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("empty ID must panic")
		}
	}()
	Register(stubScenario{id: ""})
}

func TestBindEndpointValidation(t *testing.T) {
	accepted := []string{
		"http://example.com",
		"https://example.com/mcp",
		"https://example.com:8443/mcp?mode=readonly",
		"http://[::1]:8080/mcp",
	}
	for _, endpoint := range accepted {
		t.Run("accept_"+endpoint, func(t *testing.T) {
			serverID := ingest.ResolveMCPServerIdentity("http", endpoint).ObjectID
			binding, err := BindEndpoint(endpoint, "campaign-credential", serverID)
			if err != nil {
				t.Fatalf("BindEndpoint(%q): %v", endpoint, err)
			}
			if binding.Endpoint != endpoint {
				t.Fatalf("endpoint = %q, want untouched %q", binding.Endpoint, endpoint)
			}
			if strings.Contains(binding.TargetRef, "?") {
				t.Fatalf("target reference exposed query: %q", binding.TargetRef)
			}
		})
	}

	rejected := []string{
		"",
		"/relative",
		"example.com/mcp",
		"ftp://example.com/mcp",
		"http:///missing-authority",
		"http://",
		"http://user:pass@example.com/mcp",
		"http://example.com/mcp#fragment",
		"http://[::1",
	}
	for _, endpoint := range rejected {
		t.Run("reject_"+endpoint, func(t *testing.T) {
			if _, err := BindEndpoint(endpoint, "campaign-credential", "unused"); err == nil {
				t.Fatalf("BindEndpoint(%q) unexpectedly succeeded", endpoint)
			}
		})
	}
}

func TestBindEndpointUsesUntouchedTrimmedIdentity(t *testing.T) {
	const endpoint = "HTTP://Example.COM:80/mcp?z=1&a=%2F"
	trimmed := strings.TrimSpace(endpoint)
	serverID := ingest.ResolveMCPServerIdentity("http", trimmed).ObjectID
	binding, err := BindEndpoint(" \t"+endpoint+"\n", "credential", serverID)
	if err != nil {
		t.Fatalf("BindEndpoint: %v", err)
	}
	if binding.Endpoint != endpoint {
		t.Fatalf("endpoint = %q, want exact trimmed representation %q", binding.Endpoint, endpoint)
	}

	normalizedID := ingest.ResolveMCPServerIdentity("http", "http://example.com/mcp?a=%2F&z=1").ObjectID
	if normalizedID == serverID {
		t.Fatal("test setup requires normalized spelling to have a different identity")
	}
	if _, err := BindEndpoint(endpoint, "credential", normalizedID); err == nil {
		t.Fatal("normalized spelling must not satisfy untouched endpoint identity")
	}
}

func TestBindEndpointQueryDefenseAndRedaction(t *testing.T) {
	const credential = "exact-campaign-credential"
	cases := []struct {
		name     string
		query    string
		rejected bool
	}{
		{"benign query", "mode=readonly&limit=1", false},
		{"unknown arbitrary bytes", "opaque=secret-looking-but-unknown", false},
		{"known sensitive key", "api%5Fkey=not-the-campaign-credential", true},
		{"exact campaign credential value", "opaque=exact-campaign-credential", true},
		{"different value", "opaque=other-credential", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := "https://example.com/mcp?" + tc.query
			serverID := ingest.ResolveMCPServerIdentity("http", endpoint).ObjectID
			binding, err := BindEndpoint(endpoint, credential, serverID)
			if tc.rejected {
				if err == nil {
					t.Fatal("query should be rejected")
				}
				if strings.Contains(err.Error(), tc.query) ||
					strings.Contains(err.Error(), credential) {
					t.Fatalf("error exposed query/credential: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("query should be accepted as identity input: %v", err)
			}
			if strings.Contains(binding.TargetRef, tc.query) || strings.Contains(binding.TargetRef, "?") {
				t.Fatalf("target ref exposed accepted query: %q", binding.TargetRef)
			}
		})
	}
}

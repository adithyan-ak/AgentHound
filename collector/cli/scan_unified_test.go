package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/contact"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestConfiguredMCPURLSeedsHostDiscovery(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "https://mcp.example:9443/mcp", want: "mcp.example", ok: true},
		{raw: "http://[2001:db8::1]:8080/mcp", want: "2001:db8::1", ok: true},
		{raw: "stdio://local", ok: false},
		{raw: "not a URL", ok: false},
	} {
		got, ok := configuredNetworkSeed(test.raw)
		if got != test.want || ok != test.ok {
			t.Fatalf("configuredNetworkSeed(%q) = (%q, %t), want (%q, %t)", test.raw, got, ok, test.want, test.ok)
		}
	}
}

func TestProtocolDiscoveryRetainsBothProtocolsAtSameEndpoint(t *testing.T) {
	runtime := &scanRuntime{
		artifact: &ingest.IngestData{},
		rootKey:  ingest.CollectorRootCoverageKey("scan"),
	}
	base := "http://127.0.0.1:8080"
	runtime.recordProtocolDiscoveries([]action.Target{
		{Kind: "host", Address: "127.0.0.1:8080", Meta: map[string]string{
			"protocol": "a2a", "url": base,
			"agent_card_url": base + "/.well-known/agent-card.json",
		}},
		{Kind: "host", Address: "127.0.0.1:8080", Meta: map[string]string{
			"protocol": "mcp", "url": base,
		}},
	})
	if len(runtime.targets) != 2 {
		t.Fatalf("targets = %+v, want both MCP and A2A", runtime.targets)
	}
	if len(runtime.artifact.Graph.Nodes) != 2 {
		t.Fatalf("discovery nodes = %+v, want both positive observations", runtime.artifact.Graph.Nodes)
	}
	for _, node := range runtime.artifact.Graph.Nodes {
		if len(node.ObservationDomains) != 1 || node.ObservationDomains[0] != runtime.rootKey {
			t.Fatalf("node %q domains = %v, want scan root", node.ID, node.ObservationDomains)
		}
	}
}

func TestPersistedExclusionsRebuildRecoveryContactPolicy(t *testing.T) {
	execution := ingest.NewScanExecution(ingest.ScanModeActive, false, time.Now())
	execution.Exclusions = []string{"blocked.example", "10.20.0.0/16"}
	policy, err := contact.NewPolicy(execution.Exclusions)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"BLOCKED.EXAMPLE.", "10.20.3.4"} {
		if err := policy.AdmitAddress(target); !errors.Is(err, contact.ErrExcluded) {
			t.Fatalf("recovery policy admitted %q: %v", target, err)
		}
	}
}

func TestNormalizedExclusionsAreStableAndDeduplicated(t *testing.T) {
	got := normalizedExclusions([]string{
		" Blocked.Example. ", "blocked.example", "10.20.3.9/16", "[2001:0db8::1]",
	})
	want := []string{"10.20.0.0/16", "2001:db8::1", "blocked.example"}
	if len(got) != len(want) {
		t.Fatalf("normalized exclusions = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("normalized exclusions = %v, want %v", got, want)
		}
	}
}

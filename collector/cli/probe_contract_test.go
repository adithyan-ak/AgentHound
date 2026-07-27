package cli

import (
	"testing"

	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/modules/protoscan"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func contractKey(t *testing.T, scope string, contract any) string {
	t.Helper()
	identity, err := identifyProbeContract(scope, contract)
	if err != nil {
		t.Fatalf("identify probe contract: %v", err)
	}
	return identity.CoverageKey
}

func TestNetworkProbeContractIdentityUsesExecutedSurface(t *testing.T) {
	report := networkscan.ProbeReport{
		Targets: networkscan.LogicalTargetSetIdentity([]string{"10.0.0.2", "10.0.0.1"}),
		Ports:   []int{4000, 11434},
	}
	candidates := []fingerprintCandidate{
		{id: "ollama-fingerprint", target: "ollama", version: "1.0.0"},
		{id: "jupyter-fingerprint", target: "jupyter", version: "2.0.0"},
	}
	manifest := &ingest.RulesetManifest{Entries: []ingest.RuleManifestEntry{
		{Type: "text", ID: "prompt-injection", Version: 1, SemanticSHA256: "sha256:text-a"},
		{Type: "fingerprint", ID: "unregistered", Version: 1, SemanticSHA256: "sha256:unused"},
		{Type: "fingerprint", ID: "ollama", Version: 1, SemanticSHA256: "sha256:ollama-a"},
		{Type: "detector", ID: "jupyter-native", Version: 1, SemanticSHA256: "sha256:jupyter-a"},
	}}
	base := buildNetworkProbeContract(report, candidates, manifest)
	baseKey := contractKey(t, "network", base)

	reordered := report
	reordered.Ports = []int{11434, 4000}
	reorderedContract := buildNetworkProbeContract(
		reordered,
		[]fingerprintCandidate{candidates[1], candidates[0]},
		&ingest.RulesetManifest{Entries: []ingest.RuleManifestEntry{
			manifest.Entries[3],
			manifest.Entries[2],
			{Type: "text", ID: "prompt-injection", Version: 1, SemanticSHA256: "sha256:text-b"},
			manifest.Entries[1],
		}},
	)
	if got := contractKey(t, "network", reorderedContract); got != baseKey {
		t.Fatalf("irrelevant ordering/text semantics changed key: got %q want %q", got, baseKey)
	}

	changedDetector := buildNetworkProbeContract(report, candidates, &ingest.RulesetManifest{
		Entries: []ingest.RuleManifestEntry{
			manifest.Entries[2],
			{Type: "detector", ID: "jupyter-native", Version: 1, SemanticSHA256: "sha256:jupyter-b"},
		},
	})
	if got := contractKey(t, "network", changedDetector); got == baseKey {
		t.Fatal("executed detector semantics did not change key")
	}

	changedVersion := append([]fingerprintCandidate(nil), candidates...)
	changedVersion[0].version = "1.0.1"
	if got := contractKey(
		t,
		"network",
		buildNetworkProbeContract(report, changedVersion, manifest),
	); got == baseKey {
		t.Fatal("fingerprinter version did not change key")
	}
}

func TestProtocolProbeContractIdentityIgnoresInactivePortFlags(t *testing.T) {
	targets := networkscan.LogicalTargetSetIdentity([]string{"127.0.0.1"})
	first := protoscan.ProbeReport{
		Targets: targets,
		Protocols: []protoscan.ProtocolSurface{{
			Protocol: "mcp",
			Ports:    []int{8000, 3000},
		}},
	}
	second := protoscan.ProbeReport{
		Targets: targets,
		Protocols: []protoscan.ProtocolSurface{{
			Protocol: "mcp",
			Ports:    []int{3000, 8000},
		}},
	}
	firstKey := contractKey(t, "discover", buildProtocolProbeContract(first))
	if got := contractKey(t, "discover", buildProtocolProbeContract(second)); got != firstKey {
		t.Fatalf("equivalent active surface changed key: got %q want %q", got, firstKey)
	}

	second.Protocols[0].Ports = append(second.Protocols[0].Ports, 8443)
	if got := contractKey(t, "discover", buildProtocolProbeContract(second)); got == firstKey {
		t.Fatal("active MCP port change did not change key")
	}
}

func TestProbeContractIdentityTracksExpandedTargets(t *testing.T) {
	first := networkscan.ProbeReport{
		Targets: networkscan.LogicalTargetSetIdentity([]string{"10.0.0.1"}),
		Ports:   []int{4000},
	}
	second := first
	second.Targets = networkscan.LogicalTargetSetIdentity([]string{"10.0.0.2"})

	firstKey := contractKey(
		t,
		"network",
		buildNetworkProbeContract(first, nil, ingest.EmptyRulesetManifest()),
	)
	secondKey := contractKey(
		t,
		"network",
		buildNetworkProbeContract(second, nil, ingest.EmptyRulesetManifest()),
	)
	if firstKey == secondKey {
		t.Fatal("different expanded target sets produced the same key")
	}
}

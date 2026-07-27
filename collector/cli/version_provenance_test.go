package cli

import (
	"context"
	"testing"

	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/modules/protoscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestCollectionEnvelopesPreserveInjectedCollectorVersion(t *testing.T) {
	previous := common.CollectorVersion()
	t.Cleanup(func() { common.SetCollectorVersion(previous) })

	const releaseVersion = "1.0.0-test"
	common.SetCollectorVersion(releaseVersion)

	combined, enabled, failed := collectAll(
		context.Background(), false, false, false,
		"", nil, "", "", false, false,
		"", "", nil, "", "",
		0, 0, false, false, "",
		nil, ingest.EmptyRulesetManifest(),
	)
	if enabled != 0 || failed != 0 {
		t.Fatalf("empty combined collection = %d enabled / %d failed, want 0 / 0", enabled, failed)
	}

	networkReport := networkscan.ProbeReport{
		Total:      1,
		Conclusive: 1,
		Targets:    networkscan.LogicalTargetSetIdentity([]string{"127.0.0.1"}),
		Ports:      []int{1},
	}
	networkContract := buildNetworkProbeContract(
		networkReport,
		nil,
		ingest.EmptyRulesetManifest(),
	)
	networkIdentity, err := identifyProbeContract("network", networkContract)
	if err != nil {
		t.Fatalf("identify network probe contract: %v", err)
	}
	protocolReport := protoscan.ProbeReport{
		Total:      1,
		Conclusive: 1,
		Targets:    networkscan.LogicalTargetSetIdentity([]string{"127.0.0.1"}),
		Protocols: []protoscan.ProtocolSurface{{
			Protocol: "mcp",
			Ports:    []int{1},
		}},
	}
	protocolContract := buildProtocolProbeContract(protocolReport)
	protocolIdentity, err := identifyProbeContract("discover", protocolContract)
	if err != nil {
		t.Fatalf("identify protocol probe contract: %v", err)
	}

	envelopes := map[string]*ingest.IngestData{
		"combined scan": combined,
		"network scan": buildNetworkScanEnvelope(
			"127.0.0.1:1",
			nil,
			"",
			"",
			false,
			networkIdentity,
			networkContract,
		),
		"discover": buildDiscoverEnvelope(
			"127.0.0.1:1",
			nil,
			"",
			"",
			false,
			protocolReport,
			protocolIdentity,
			protocolContract,
		),
		"loot":     buildLootEnvelope("http://127.0.0.1", "jupyter", "ENG", &action.LootResult{}),
		"extract":  buildExtractEnvelope(ingest.ComputeNodeID("AIModel", "instance", "model"), "embedding-inversion", "ENG", &action.ExtractResult{}),
		"campaign": buildCampaignEnvelope("cred-reach", 1, "ENG", campTestEvidence(campaign.OutcomeNotObserved)),
	}
	for name, envelope := range envelopes {
		if got := envelope.Meta.CollectorVersion; got != releaseVersion {
			t.Errorf("%s collector_version = %q, want injected release version %q", name, got, releaseVersion)
		}
	}
}

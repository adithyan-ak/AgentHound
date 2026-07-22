package cli

import (
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestPrepareCollectorArtifactUsesInternalIdentityProviderAndExplicitParentage(t *testing.T) {
	original := deriveCollectionIdentity
	t.Cleanup(func() { deriveCollectionIdentity = original })
	wantIdentity := ingest.NewCollectionIdentity(
		[]ingest.IdentityEvidence{
			{Kind: "os_instance", Digest: "hmac-sha256:" + strings.Repeat("a", 64)},
			{Kind: "principal", Digest: "hmac-sha256:" + strings.Repeat("b", 64)},
		},
		[]ingest.IdentityEvidence{{Kind: "network_profile", Digest: "hmac-sha256:" + strings.Repeat("c", 64)}},
		ingest.NetworkClassPrivate,
	)
	var receivedScanID string
	deriveCollectionIdentity = func(scanID string) ingest.CollectionIdentity {
		receivedScanID = scanID
		return wantIdentity
	}

	data := common.NewIngestData("mcp", "identity-provider-test")
	child := ingest.CanonicalCoverageKey("mcp", "target", "https://service.internal")
	root := ingest.CollectorRootCoverageKey("mcp")
	data.Meta.Collection = &ingest.CollectionReport{
		State:        ingest.OutcomeComplete,
		CoverageKeys: []string{root, child},
		AuthoritativeRoots: []ingest.CoverageRoot{{
			CoverageKey: root, ChildCoverageKeys: []string{child},
		}},
		Outcomes: []ingest.CollectionOutcome{
			{Collector: "mcp", CoverageKey: root, Target: "mcp", Method: "collect", State: ingest.OutcomeComplete},
			{Collector: "mcp", CoverageKey: child, Target: "https://service.internal", Method: "enumerate", State: ingest.OutcomeComplete},
		},
	}
	if err := prepareCollectorArtifact(data); err != nil {
		t.Fatal(err)
	}
	if receivedScanID != data.Meta.ScanID || data.Meta.Identity.CollectionPointID != wantIdentity.CollectionPointID {
		t.Fatalf("identity provider received %q and emitted %+v", receivedScanID, data.Meta.Identity)
	}
	parents := ingest.CoverageParents(data.Meta.Collection)
	if parents[child] != root {
		t.Fatalf("coverage parents = %+v, want %s -> %s", parents, child, root)
	}
}

package identity

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestDeriveEmitsValidatedDisplayAndIndependentQuality(t *testing.T) {
	identity := Derive("native-identity-test")
	if err := identity.Validate(); err != nil {
		t.Fatalf("native identity invalid: %v", err)
	}
	if identity.Display.OS != runtime.GOOS || identity.Display.Architecture != runtime.GOARCH {
		t.Fatalf("display = %+v", identity.Display)
	}
	if identity.NetworkQuality != ingest.IdentityQualityStrong &&
		identity.NetworkQuality != ingest.IdentityQualityUnknown {
		t.Fatalf("network quality = %q", identity.NetworkQuality)
	}
}

func TestStrongIdentityIgnoresWeakFallbackSignals(t *testing.T) {
	platform := []rawSignal{
		{kind: "os_instance", value: "machine-a"},
		{kind: "platform", value: "platform-a"},
		{kind: "principal", value: "principal-a"},
	}
	network := []rawSignal{{kind: "network_profile", value: "profile-a"}}
	first := deriveFromSignals(
		"scan-a",
		platform,
		network,
		[]rawSignal{{kind: "hostname", value: "before"}, {kind: "mac", value: "00:11:22:33:44:55"}},
		nil,
	)
	second := deriveFromSignals(
		"scan-b",
		platform,
		network,
		[]rawSignal{{kind: "hostname", value: "after"}, {kind: "mac", value: "00:11:22:33:44:66"}},
		nil,
	)

	if first.CollectionPointID != second.CollectionPointID {
		t.Fatalf("strong collection point changed with fallback evidence: %q != %q", first.CollectionPointID, second.CollectionPointID)
	}
	if first.NetworkContextID != second.NetworkContextID {
		t.Fatalf("network context changed with ignored fallback evidence: %q != %q", first.NetworkContextID, second.NetworkContextID)
	}
	if first.Quality != ingest.IdentityQualityStrong {
		t.Fatalf("quality = %q, want strong", first.Quality)
	}
	for _, evidence := range first.Evidence {
		if evidence.Kind == "hostname" || evidence.Kind == "mac" {
			t.Fatalf("strong identity retained weak fallback evidence: %+v", first.Evidence)
		}
	}
}

func TestNetworkChangesDoNotChangeCollectionPoint(t *testing.T) {
	platform := []rawSignal{
		{kind: "os_instance", value: "machine-a"},
		{kind: "principal", value: "principal-a"},
	}
	first := deriveFromSignals(
		"scan-a",
		platform,
		nil,
		nil,
		[]rawSignal{{kind: "route_private", value: "10.0.0.0/24"}},
	)
	second := deriveFromSignals(
		"scan-b",
		platform,
		nil,
		nil,
		[]rawSignal{{kind: "route_private", value: "10.1.0.0/24"}},
	)

	if first.CollectionPointID != second.CollectionPointID {
		t.Fatal("network change altered collection-point identity")
	}
	if first.NetworkContextID == second.NetworkContextID {
		t.Fatal("different observable networks produced the same network context")
	}
}

func TestWeakFallbackAndOpaqueArtifactIdentity(t *testing.T) {
	weak := deriveFromSignals(
		"scan-a",
		[]rawSignal{{kind: "principal", value: "1000"}},
		nil,
		[]rawSignal{{kind: "hostname", value: "red-host"}},
		nil,
	)
	if weak.Quality != ingest.IdentityQualityWeak {
		t.Fatalf("fallback quality = %q, want weak", weak.Quality)
	}
	if weak.NetworkClass != ingest.NetworkClassOffline {
		t.Fatalf("fallback network class = %q, want offline", weak.NetworkClass)
	}
	if err := weak.Validate(); err != nil {
		t.Fatalf("weak fallback identity is invalid: %v", err)
	}

	opaqueA := deriveFromSignals("scan-a", nil, nil, nil, nil)
	opaqueB := deriveFromSignals("scan-b", nil, nil, nil, nil)
	if opaqueA.CollectionPointID == opaqueB.CollectionPointID {
		t.Fatal("fully opaque artifacts did not receive artifact-distinct evidence")
	}
}

func TestIdentityArtifactContainsOnlyHMACedSignals(t *testing.T) {
	identity := deriveFromSignals(
		"scan-secret",
		[]rawSignal{
			{kind: "os_instance", value: "raw-machine-secret"},
			{kind: "principal", value: "raw-principal-secret"},
		},
		nil,
		nil,
		[]rawSignal{
			{kind: "dns_domain", value: "sensitive.internal"},
			{kind: "route_private", value: "10.20.0.0/16\x00next_hop=192.168.1.10\x00path=profile=pivot-secret"},
		},
	)
	wire, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"raw-machine-secret",
		"raw-principal-secret",
		"sensitive.internal",
		"10.20.0.0/16",
		"192.168.1.10",
		"pivot-secret",
	} {
		if strings.Contains(string(wire), raw) {
			t.Fatalf("identity artifact leaked raw evidence %q: %s", raw, wire)
		}
	}
	for _, evidence := range append(identity.Evidence, identity.NetworkEvidence...) {
		if !strings.HasPrefix(evidence.Digest, "hmac-sha256:") || len(evidence.Digest) != len("hmac-sha256:")+64 {
			t.Fatalf("non-HMAC evidence emitted: %+v", evidence)
		}
	}
}

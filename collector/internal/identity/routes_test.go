package identity

import (
	"net"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestCanonicalRouteSignalsRetainsPrivateIPv4AndULA(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		prefix      int
		want        string
	}{
		{name: "split IPv4", destination: "10.20.5.4", prefix: 16, want: "10.20.0.0/16"},
		{name: "IPv6 ULA", destination: "fd12:3456:789a::1", prefix: 48, want: "fd12:3456:789a::/48"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signals, complete := canonicalRouteSignals(
				net.ParseIP(tt.destination), tt.prefix, nil, "profile=pivot-a",
			)
			want := tt.want + "\x00path=profile=pivot-a"
			if !complete || len(signals) != 1 || signals[0].kind != "route_private" || signals[0].value != want {
				t.Fatalf("signals = %+v complete=%v, want private route %q", signals, complete, want)
			}
		})
	}
}

func TestCanonicalRouteSignalsExcludesPublicDestinationsAndKeepsGateway(t *testing.T) {
	if signals, complete := canonicalRouteSignals(net.ParseIP("203.0.113.0"), 24, nil, ""); len(signals) != 0 || !complete {
		t.Fatalf("public route retained: %+v", signals)
	}
	signals, complete := canonicalRouteSignals(net.IPv4zero, 0, net.ParseIP("192.168.1.1"), "")
	if !complete || len(signals) != 1 || signals[0] != (rawSignal{kind: "default_gateway", value: "next_hop=192.168.1.1"}) {
		t.Fatalf("default gateway signals = %+v complete=%v", signals, complete)
	}
}

func TestSamePrefixThroughDifferentPathsProducesDifferentNetworkContexts(t *testing.T) {
	pivotA, completeA := canonicalRouteSignals(
		net.ParseIP("10.20.0.0"), 16, nil, "profile=pivot-a",
	)
	pivotB, completeB := canonicalRouteSignals(
		net.ParseIP("10.20.0.0"), 16, nil, "profile=pivot-b",
	)
	if !completeA || !completeB {
		t.Fatal("distinguishable route paths reported incomplete")
	}

	platform := []rawSignal{
		{kind: "os_instance", value: "machine-a"},
		{kind: "principal", value: "principal-a"},
	}
	first := deriveFromSignals("scan-a", platform, pivotA, nil, nil)
	second := deriveFromSignals("scan-b", platform, pivotB, nil, nil)

	if first.CollectionPointID != second.CollectionPointID {
		t.Fatal("route path altered collection-point identity")
	}
	if first.NetworkContextID == second.NetworkContextID {
		t.Fatal("identical prefixes through different paths collapsed into one network context")
	}
}

func TestSamePrefixThroughDifferentNextHopsProducesDifferentNetworkContexts(t *testing.T) {
	pivotA, completeA := canonicalRouteSignals(
		net.ParseIP("10.20.0.0"), 16, net.ParseIP("192.168.1.10"), "link=00:11:22:33:44:55",
	)
	pivotB, completeB := canonicalRouteSignals(
		net.ParseIP("10.20.0.0"), 16, net.ParseIP("192.168.1.11"), "link=00:11:22:33:44:55",
	)
	if !completeA || !completeB {
		t.Fatal("distinguishable route next hops reported incomplete")
	}

	platform := []rawSignal{
		{kind: "os_instance", value: "machine-a"},
		{kind: "principal", value: "principal-a"},
	}
	first := deriveFromSignals("scan-a", platform, pivotA, nil, nil)
	second := deriveFromSignals("scan-b", platform, pivotB, nil, nil)
	if first.NetworkContextID == second.NetworkContextID {
		t.Fatal("identical prefixes through different next hops collapsed into one network context")
	}
}

func TestPrivateRouteWithoutPathMakesOnlyNetworkQualityUnknown(t *testing.T) {
	routes, complete := canonicalRouteSignals(net.ParseIP("10.20.0.0"), 16, nil, "")
	if complete || len(routes) != 1 {
		t.Fatalf("signals = %+v complete=%v, want retained incomplete private route", routes, complete)
	}
	routes = append(routes, rawSignal{kind: "network_visibility_unknown", value: "route_table"})
	identity := deriveFromSignals(
		"scan-a",
		[]rawSignal{{kind: "os_instance", value: "machine-a"}, {kind: "principal", value: "principal-a"}},
		routes,
		nil,
		nil,
	)
	if identity.Quality != ingest.IdentityQualityStrong {
		t.Fatalf("collection-point quality = %q, want strong", identity.Quality)
	}
	if identity.NetworkQuality != ingest.IdentityQualityUnknown {
		t.Fatalf("network quality = %q, want unknown", identity.NetworkQuality)
	}
	if identity.NetworkClass != ingest.NetworkClassPrivate {
		t.Fatalf("network class = %q, want retained private classification", identity.NetworkClass)
	}
}

func TestStableLinkAddressRejectsSentinels(t *testing.T) {
	if got := stableLinkAddress([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}); got != "00:11:22:33:44:55" {
		t.Fatalf("stable link address = %q", got)
	}
	for _, invalid := range [][]byte{
		{0, 0, 0, 0, 0, 0},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x00, 0x11, 0x22},
	} {
		if got := stableLinkAddress(invalid); got != "" {
			t.Fatalf("invalid address %v accepted as %q", invalid, got)
		}
	}
}

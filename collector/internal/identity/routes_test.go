package identity

import (
	"net"
	"testing"
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
			signals := canonicalRouteSignals(net.ParseIP(tt.destination), tt.prefix, nil)
			if len(signals) != 1 || signals[0].kind != "route_private" || signals[0].value != tt.want {
				t.Fatalf("signals = %+v, want private route %q", signals, tt.want)
			}
		})
	}
}

func TestCanonicalRouteSignalsExcludesPublicDestinationsAndKeepsGateway(t *testing.T) {
	if signals := canonicalRouteSignals(net.ParseIP("203.0.113.0"), 24, nil); len(signals) != 0 {
		t.Fatalf("public route retained: %+v", signals)
	}
	signals := canonicalRouteSignals(net.IPv4zero, 0, net.ParseIP("192.168.1.1"))
	if len(signals) != 1 || signals[0] != (rawSignal{kind: "default_gateway", value: "192.168.1.1"}) {
		t.Fatalf("default gateway signals = %+v", signals)
	}
}

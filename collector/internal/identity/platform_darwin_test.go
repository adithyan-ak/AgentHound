//go:build darwin

package identity

import (
	"syscall"
	"testing"

	"golang.org/x/net/route"
)

func TestDarwinTransientNeighborRoutesDoNotChangeNetworkContext(t *testing.T) {
	stableAddrs := make([]route.Addr, syscall.RTAX_MAX)
	stableAddrs[syscall.RTAX_DST] = &route.Inet4Addr{IP: [4]byte{10, 20, 0, 0}}
	stableAddrs[syscall.RTAX_GATEWAY] = &route.Inet4Addr{IP: [4]byte{192, 168, 1, 10}}
	stableAddrs[syscall.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte{255, 255, 0, 0}}
	stable := &route.RouteMessage{Flags: syscall.RTF_UP, Addrs: stableAddrs}

	neighborAddrs := make([]route.Addr, syscall.RTAX_MAX)
	neighborAddrs[syscall.RTAX_DST] = &route.Inet4Addr{IP: [4]byte{10, 20, 0, 55}}
	neighborAddrs[syscall.RTAX_GATEWAY] = &route.LinkAddr{Addr: []byte{0, 17, 34, 51, 68, 85}}
	neighbor := &route.RouteMessage{
		Flags: syscall.RTF_UP | syscall.RTF_HOST | syscall.RTF_LLINFO,
		Addrs: neighborAddrs,
	}
	cloned := &route.RouteMessage{
		Flags: syscall.RTF_UP | syscall.RTF_HOST | syscall.RTF_WASCLONED,
		Addrs: neighborAddrs,
	}

	baseSignals, baseComplete := darwinRouteSignalsFromMessages([]route.Message{stable})
	cacheSignals, cacheComplete := darwinRouteSignalsFromMessages([]route.Message{stable, neighbor, cloned})
	if !baseComplete || !cacheComplete {
		t.Fatalf("route visibility unexpectedly incomplete: base=%v cache=%v", baseComplete, cacheComplete)
	}
	platform := []rawSignal{
		{kind: "os_instance", value: "machine-a"},
		{kind: "principal", value: "principal-a"},
	}
	withoutCache := deriveFromSignals("scan-a", platform, baseSignals, nil, nil)
	withCache := deriveFromSignals("scan-b", platform, cacheSignals, nil, nil)
	if withoutCache.NetworkContextID != withCache.NetworkContextID {
		t.Fatalf("transient neighbor routes changed network context: %q != %q", withoutCache.NetworkContextID, withCache.NetworkContextID)
	}
}

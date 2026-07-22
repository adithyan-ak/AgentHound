package identity

import (
	"net"
	"strings"
)

// canonicalRouteSignals retains only route-table facts that define private
// visibility plus default gateways. A private prefix is bound to every
// observable path component so overlapping client networks reached through
// different pivots cannot collapse. Metrics, interface names, source routes,
// and public destination routes are deliberately excluded.
//
// The boolean reports whether the retained route had enough next-hop or stable
// link/profile evidence to distinguish its path. Callers downgrade only
// network-context quality when it is false.
func canonicalRouteSignals(
	destination net.IP,
	prefixLength int,
	gateway net.IP,
	pathDiscriminator string,
) ([]rawSignal, bool) {
	bits := 128
	if ip4 := destination.To4(); ip4 != nil {
		destination = ip4
		bits = 32
	} else if ip6 := destination.To16(); ip6 != nil {
		destination = ip6
	} else {
		return nil, false
	}
	if prefixLength < 0 || prefixLength > bits {
		return nil, false
	}
	pathDiscriminator = strings.TrimSpace(pathDiscriminator)
	nextHop := canonicalIP(gateway)
	hasNextHop := usableGateway(nextHop)
	if prefixLength == 0 && destination.IsUnspecified() {
		parts := make([]string, 0, 2)
		if hasNextHop {
			parts = append(parts, "next_hop="+nextHop.String())
		}
		if pathDiscriminator != "" {
			parts = append(parts, "path="+pathDiscriminator)
		}
		if len(parts) == 0 {
			return nil, false
		}
		return []rawSignal{{kind: "default_gateway", value: strings.Join(parts, "\x00")}}, true
	}
	mask := net.CIDRMask(prefixLength, bits)
	networkIP := destination.Mask(mask)
	if networkIP == nil || !networkIP.IsPrivate() {
		return nil, true
	}
	parts := []string{(&net.IPNet{IP: networkIP, Mask: mask}).String()}
	if hasNextHop {
		parts = append(parts, "next_hop="+nextHop.String())
	}
	if pathDiscriminator != "" {
		parts = append(parts, "path="+pathDiscriminator)
	}
	return []rawSignal{{
		kind:  "route_private",
		value: strings.Join(parts, "\x00"),
	}}, hasNextHop || pathDiscriminator != ""
}

func usableGateway(ip net.IP) bool {
	ip = canonicalIP(ip)
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
}

func canonicalIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

func stableLinkAddress(address []byte) string {
	if len(address) < 6 || len(address) > 32 {
		return ""
	}
	allZero, allBroadcast := true, true
	for _, value := range address {
		allZero = allZero && value == 0
		allBroadcast = allBroadcast && value == 0xff
	}
	if allZero || allBroadcast {
		return ""
	}
	return strings.ToLower(net.HardwareAddr(address).String())
}

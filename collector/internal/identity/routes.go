package identity

import "net"

// canonicalRouteSignals retains only route-table facts that define private
// visibility plus default gateways. Metrics, interface names, source routes,
// and public destination routes are deliberately excluded.
func canonicalRouteSignals(destination net.IP, prefixLength int, gateway net.IP) []rawSignal {
	bits := 128
	if ip4 := destination.To4(); ip4 != nil {
		destination = ip4
		bits = 32
	} else if ip6 := destination.To16(); ip6 != nil {
		destination = ip6
	} else {
		return nil
	}
	if prefixLength < 0 || prefixLength > bits {
		return nil
	}
	if prefixLength == 0 && destination.IsUnspecified() {
		if usableGateway(gateway) {
			return []rawSignal{{kind: "default_gateway", value: canonicalIP(gateway).String()}}
		}
		return nil
	}
	mask := net.CIDRMask(prefixLength, bits)
	networkIP := destination.Mask(mask)
	if networkIP == nil || !networkIP.IsPrivate() {
		return nil
	}
	return []rawSignal{{
		kind:  "route_private",
		value: (&net.IPNet{IP: networkIP, Mask: mask}).String(),
	}}
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

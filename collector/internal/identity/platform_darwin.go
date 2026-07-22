//go:build darwin

package identity

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func platformSignals() ([]rawSignal, []rawSignal, bool) {
	var identity []rawSignal
	var stat unix.Statfs_t
	if err := unix.Statfs("/", &stat); err == nil {
		identity = append(identity, rawSignal{
			kind:  "os_instance",
			value: fmt.Sprintf("%08x%08x", uint32(stat.Fsid.Val[0]), uint32(stat.Fsid.Val[1])),
		})
	}
	if value, err := unix.Sysctl("kern.uuid"); err == nil && value != "" {
		identity = append(identity, rawSignal{kind: "platform", value: value})
	}
	identity = append(identity, rawSignal{kind: "principal", value: strconv.Itoa(os.Geteuid())})
	network, complete := darwinRouteSignals()
	return identity, network, complete
}

func darwinRouteSignals() ([]rawSignal, bool) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, false
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, false
	}
	var signals []rawSignal
	complete := true
	for _, raw := range messages {
		message, ok := raw.(*route.RouteMessage)
		if !ok || message.Flags&syscall.RTF_UP == 0 || len(message.Addrs) <= syscall.RTAX_DST {
			continue
		}
		destination := darwinRouteIP(message.Addrs[syscall.RTAX_DST])
		if destination == nil {
			continue
		}
		bits := 128
		if destination.To4() != nil {
			bits = 32
		}
		prefixLength, ok := darwinRoutePrefixLength(message, bits)
		if !ok {
			complete = false
			continue
		}
		var gateway net.IP
		if len(message.Addrs) > syscall.RTAX_GATEWAY {
			gateway = darwinRouteIP(message.Addrs[syscall.RTAX_GATEWAY])
		}
		routeSignals, routeComplete := canonicalRouteSignals(
			destination,
			prefixLength,
			gateway,
			darwinRoutePathDiscriminator(message),
		)
		signals = append(signals, routeSignals...)
		complete = complete && routeComplete
	}
	return signals, complete
}

func darwinRoutePathDiscriminator(message *route.RouteMessage) string {
	for _, index := range []int{syscall.RTAX_IFP, syscall.RTAX_GATEWAY} {
		if len(message.Addrs) <= index {
			continue
		}
		link, ok := message.Addrs[index].(*route.LinkAddr)
		if !ok {
			continue
		}
		if address := stableLinkAddress(link.Addr); address != "" {
			return "link=" + address
		}
		if address := darwinInterfaceLinkAddress(link.Index); address != "" {
			return "link=" + address
		}
	}
	if address := darwinInterfaceLinkAddress(message.Index); address != "" {
		return "link=" + address
	}
	return ""
}

func darwinInterfaceLinkAddress(index int) string {
	if index <= 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return stableLinkAddress(iface.HardwareAddr)
}

func darwinRoutePrefixLength(message *route.RouteMessage, bits int) (int, bool) {
	if message.Flags&syscall.RTF_HOST != 0 {
		return bits, true
	}
	if len(message.Addrs) <= syscall.RTAX_NETMASK || message.Addrs[syscall.RTAX_NETMASK] == nil {
		return 0, darwinRouteIP(message.Addrs[syscall.RTAX_DST]).IsUnspecified()
	}
	maskIP := darwinRouteIP(message.Addrs[syscall.RTAX_NETMASK])
	if maskIP == nil {
		return 0, false
	}
	if bits == 32 {
		maskIP = maskIP.To4()
	} else {
		maskIP = maskIP.To16()
	}
	ones, maskBits := net.IPMask(maskIP).Size()
	return ones, maskBits == bits
}

func darwinRouteIP(address route.Addr) net.IP {
	switch value := address.(type) {
	case *route.Inet4Addr:
		return net.IPv4(value.IP[0], value.IP[1], value.IP[2], value.IP[3])
	case *route.Inet6Addr:
		return net.IP(value.IP[:])
	default:
		return nil
	}
}

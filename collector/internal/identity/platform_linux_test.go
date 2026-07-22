//go:build linux

package identity

import (
	"strings"
	"testing"
)

func TestParseLinuxIPv4RoutesIncludesSplitRoutes(t *testing.T) {
	routes := `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
tun0 0000140A 00000000 0001 0 0 0 0000FFFF 0 0 0
eth0 00000000 0101A8C0 0003 0 0 0 00000000 0 0 0
`
	signals, complete := parseLinuxIPv4Routes(strings.NewReader(routes))
	if !complete || !hasRawSignal(signals, "route_private", "10.20.0.0/16") ||
		!hasRawSignal(signals, "default_gateway", "192.168.1.1") {
		t.Fatalf("signals = %+v complete=%v", signals, complete)
	}
}

func TestParseLinuxIPv6RoutesIncludesULA(t *testing.T) {
	routes := `fd123456789a00000000000000000000 30 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 tun0
`
	signals, complete := parseLinuxIPv6Routes(strings.NewReader(routes))
	if !complete || !hasRawSignal(signals, "route_private", "fd12:3456:789a::/48") {
		t.Fatalf("signals = %+v complete=%v", signals, complete)
	}
}

func TestPrivateCgroupNamespaceNeedsFilesystemFallback(t *testing.T) {
	if identity := linuxContainerIdentityFrom("0::/\n"); identity != "" {
		t.Fatalf("private cgroup namespace fabricated container ID %q", identity)
	}
	mountInfo := `42 35 0:38 / / rw,relatime - overlay overlay rw
`
	if filesystem := linuxRootFilesystemType(strings.NewReader(mountInfo)); filesystem != "overlay" {
		t.Fatalf("root filesystem = %q, want overlay", filesystem)
	}
}

func TestMalformedLinuxRouteTableIsIncomplete(t *testing.T) {
	_, complete := parseLinuxIPv4Routes(strings.NewReader("eth0 not-a-route\n"))
	if complete {
		t.Fatal("malformed route table reported complete visibility")
	}
}

func hasRawSignal(signals []rawSignal, kind, value string) bool {
	for _, signal := range signals {
		if signal.kind == kind && signal.value == value {
			return true
		}
	}
	return false
}

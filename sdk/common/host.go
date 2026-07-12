package common

import (
	"net"
	"net/url"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type HostInfo struct {
	Hostname  string
	IP        string
	IsLocal   bool
	IsPrivate bool
	IsPublic  bool
	// IsLinkLocal is true for IPv4 169.254.0.0/16 (excluding the EC2/AWS
	// metadata literal 169.254.169.254 which is treated as private — see
	// isPrivate) and IPv6 fe80::/10. The network scanner refuses these
	// addresses outright; they cannot route off-host.
	IsLinkLocal bool
	// IsMulticast is true for IPv4 224.0.0.0/4 and IPv6 ff00::/8. Refused
	// by the scanner — multicast is not a unicast scanning target.
	IsMulticast bool
}

func ClassifyHost(hostOrURL string) HostInfo {
	host := hostOrURL

	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
	}

	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	info := HostInfo{}

	if ip := net.ParseIP(host); ip != nil {
		info.IP = ip.String()
	} else {
		info.Hostname = host
	}

	// Link-local + multicast classification is layered on top of the
	// local/private/public ternary so existing callers that key only on
	// IsLocal/IsPrivate/IsPublic keep working. The scanner consults
	// IsLinkLocal/IsMulticast separately to refuse those targets even
	// when they happen to fall in a private CIDR.
	if isMulticast(host) {
		info.IsMulticast = true
	}
	if isLinkLocal(host) {
		info.IsLinkLocal = true
	}

	if isLocal(host) {
		info.IsLocal = true
		return info
	}
	if isPrivate(host) {
		info.IsPrivate = true
		return info
	}

	info.IsPublic = true
	return info
}

func HostNodeID(hostname string) string {
	return ingest.ComputeNodeID("Host", hostname)
}

// Scope returns the coarse network scope of the host: "local", "private",
// "public", or "unknown". A "public" verdict is only returned for an actual
// resolved IP — a bare hostname is reported as "unknown" because its scope
// depends on DNS resolution the collector did not perform (absence of a
// private/local match is not evidence a hostname is public).
func (h HostInfo) Scope() string {
	switch {
	case h.IsLocal:
		return "local"
	case h.IsPrivate:
		return "private"
	case h.IsPublic && h.IP != "":
		return "public"
	default:
		return "unknown"
	}
}

// ScopeState reports whether the host scope was actually assessed. A resolved
// IP, or the definitively-local "localhost", is assessed; a bare unresolved
// hostname is not_assessed.
func (h HostInfo) ScopeState() AssessmentState {
	if h.IsLocal || h.IsPrivate || h.IP != "" {
		return AssessmentAssessed
	}
	return AssessmentNotAssessed
}

// HostNodeProps builds the canonical property map for a Host node from a
// classified HostInfo. It carries the local/private/public booleans (kept for
// existing consumers) plus the derived host_scope and host_scope_state so an
// unassessed hostname is not silently read as public.
func HostNodeProps(info HostInfo) map[string]any {
	return map[string]any{
		"hostname":         info.Hostname,
		"ip":               info.IP,
		"is_local":         info.IsLocal,
		"is_private":       info.IsPrivate,
		"is_public":        info.IsPublic,
		"host_scope":       info.Scope(),
		"host_scope_state": string(info.ScopeState()),
	}
}

func isLocal(host string) bool {
	lower := strings.ToLower(host)
	if lower == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() {
		return true
	}

	return false
}

func isPrivate(host string) bool {
	if host == "169.254.169.254" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	privateRanges := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		// IPv6 unique local addresses (RFC 4193).
		{mustParseCIDR("fc00::/7")},
	}

	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}

	return false
}

// isLinkLocal reports whether the host is link-local *unicast* — IPv4
// 169.254.0.0/16 or IPv6 fe80::/10. Link-local multicast addresses
// (224.0.0.0/24, ff02::/16) are reported by isMulticast instead so the two
// flags stay disjoint. The AWS/Azure/GCP metadata literal 169.254.169.254
// is classified as private (preserved from v0.1).
func isLinkLocal(host string) bool {
	if host == "169.254.169.254" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLinkLocalUnicast()
}

// isMulticast reports whether the host is in IPv4 224.0.0.0/4 or IPv6 ff00::/8.
func isMulticast(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsMulticast()
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("invalid CIDR: " + cidr)
	}
	return network
}

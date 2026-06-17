package action

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target is the input shape for every per-target action (Fingerprint,
// Enumerate, Loot, Extract, Poison, Implant). v0 keeps it deliberately flat
// — Kind discriminates and Meta carries discovery hints. Typed sub-structs
// (HostTarget, URLTarget, ConfigTarget, etc.) may land at v1 if real
// consumers demand stronger typing.
type Target struct {
	Kind    string            // "host", "url", "config_path", "cidr_member", "local"
	Address string            // "10.0.0.42:11434", "https://api.example.com", ""
	Meta    map[string]string // discovery hints; conventions documented per Kind
}

// EndpointParts returns the scheme, host, and port for network-like targets.
// URL-shaped Address values keep their URL scheme unless Meta["scheme"]
// explicitly overrides it. Host-shaped values keep the historical default
// scheme and default port behavior used by fingerprinter and looter modules.
func EndpointParts(t Target, defaultPort int, defaultScheme string) (string, string, int) {
	if defaultScheme == "" {
		defaultScheme = "http"
	}
	scheme := defaultScheme
	if s := strings.TrimSpace(t.Meta["scheme"]); s != "" {
		scheme = s
	}

	addr := strings.TrimSpace(t.Address)
	if u, err := url.Parse(addr); err == nil && u.Scheme != "" && u.Host != "" {
		if t.Meta["scheme"] == "" {
			scheme = u.Scheme
		}
		host := u.Hostname()
		port := defaultPort
		if p := u.Port(); p != "" {
			if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
				port = parsed
			}
		}
		return scheme, host, port
	}

	host := addr
	port := defaultPort
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host = h
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			port = parsed
		}
	} else if i := strings.LastIndexByte(addr, ':'); i > 0 {
		var parsed int
		if _, err := fmt.Sscanf(addr[i+1:], "%d", &parsed); err == nil && parsed > 0 {
			host = addr[:i]
			port = parsed
		}
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return scheme, host, port
}

// EndpointBaseURL returns an http(s) base URL for a target. Meta["url"] is an
// explicit override; otherwise the URL is reconstructed from EndpointParts.
func EndpointBaseURL(t Target, defaultPort int, defaultScheme string) string {
	if u := strings.TrimSpace(t.Meta["url"]); u != "" {
		return strings.TrimRight(u, "/")
	}
	scheme, host, port := EndpointParts(t, defaultPort, defaultScheme)
	if port > 0 {
		return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

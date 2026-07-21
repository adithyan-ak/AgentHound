package common

import (
	"strings"
	"testing"
)

func TestClassifyHost(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantHost  string
		wantIP    string
		wantLocal bool
		wantPriv  bool
		wantPub   bool
	}{
		{
			name:      "localhost string",
			input:     "localhost",
			wantHost:  "localhost",
			wantLocal: true,
		},
		{
			name:      "localhost uppercase",
			input:     "LOCALHOST",
			wantHost:  "LOCALHOST",
			wantLocal: true,
		},
		{
			name:      "loopback ipv4",
			input:     "127.0.0.1",
			wantIP:    "127.0.0.1",
			wantLocal: true,
		},
		{
			name:      "loopback range",
			input:     "127.0.1.1",
			wantIP:    "127.0.1.1",
			wantLocal: true,
		},
		{
			name:      "loopback ipv6",
			input:     "::1",
			wantIP:    "::1",
			wantLocal: true,
		},
		{
			name:     "private 10.x",
			input:    "10.0.0.5",
			wantIP:   "10.0.0.5",
			wantPriv: true,
		},
		{
			name:     "private 172.16.x",
			input:    "172.16.0.1",
			wantIP:   "172.16.0.1",
			wantPriv: true,
		},
		{
			name:     "private 172.31.x",
			input:    "172.31.255.255",
			wantIP:   "172.31.255.255",
			wantPriv: true,
		},
		{
			name:    "not private 172.32.x",
			input:   "172.32.0.1",
			wantIP:  "172.32.0.1",
			wantPub: true,
		},
		{
			name:     "private 192.168.x",
			input:    "192.168.1.100",
			wantIP:   "192.168.1.100",
			wantPriv: true,
		},
		{
			name:     "cloud metadata",
			input:    "169.254.169.254",
			wantIP:   "169.254.169.254",
			wantPriv: true,
		},
		{
			name:    "public ip",
			input:   "8.8.8.8",
			wantIP:  "8.8.8.8",
			wantPub: true,
		},
		{
			name:     "hostname scope is unknown without resolution",
			input:    "api.example.com",
			wantHost: "api.example.com",
		},
		{
			name:      "url with localhost",
			input:     "http://localhost:8080/api",
			wantHost:  "localhost",
			wantLocal: true,
		},
		{
			name:     "url with private ip",
			input:    "https://192.168.1.1:443/mcp",
			wantIP:   "192.168.1.1",
			wantPriv: true,
		},
		{
			name:     "url hostname scope is unknown without resolution",
			input:    "https://mcp.example.com/v1",
			wantHost: "mcp.example.com",
		},
		{
			name:      "url with 127 ip",
			input:     "http://127.0.0.1:3000",
			wantIP:    "127.0.0.1",
			wantLocal: true,
		},
		{
			name:     "url with 10.x ip",
			input:    "http://10.0.0.50:9090",
			wantIP:   "10.0.0.50",
			wantPriv: true,
		},
		{
			name:  "empty string",
			input: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyHost(tt.input)

			if tt.wantHost != "" && got.Hostname != tt.wantHost {
				t.Errorf("Hostname = %q, want %q", got.Hostname, tt.wantHost)
			}
			if tt.wantIP != "" && got.IP != tt.wantIP {
				t.Errorf("IP = %q, want %q", got.IP, tt.wantIP)
			}
			if got.IsLocal != tt.wantLocal {
				t.Errorf("IsLocal = %v, want %v", got.IsLocal, tt.wantLocal)
			}
			if got.IsPrivate != tt.wantPriv {
				t.Errorf("IsPrivate = %v, want %v", got.IsPrivate, tt.wantPriv)
			}
			if got.IsPublic != tt.wantPub {
				t.Errorf("IsPublic = %v, want %v", got.IsPublic, tt.wantPub)
			}

			flagCount := 0
			if got.IsLocal {
				flagCount++
			}
			if got.IsPrivate {
				flagCount++
			}
			if got.IsPublic {
				flagCount++
			}
			expectedFlags := 1
			var expectedScope HostScope
			switch {
			case tt.wantLocal:
				expectedScope = HostScopeLocal
			case tt.wantPriv:
				expectedScope = HostScopePrivate
			case tt.wantPub:
				expectedScope = HostScopePublic
			default:
				expectedFlags = 0
				expectedScope = HostScopeUnknown
			}
			if flagCount != expectedFlags {
				t.Errorf("scope flags = %d, want %d (local=%v private=%v public=%v)",
					flagCount, expectedFlags, got.IsLocal, got.IsPrivate, got.IsPublic)
			}
			if got.Scope != expectedScope {
				t.Errorf("Scope = %q, want %q", got.Scope, expectedScope)
			}
		})
	}
}

// TestClassifyHost_v0_2 covers the IPv6 + link-local + multicast
// classifications. The scanner refuses link-local and
// multicast targets outright, so the classification is load-bearing for
// safety, not just metadata.
func TestClassifyHost_v0_2(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		linkLocal bool
		multicast bool
		isPrivate bool
		isPublic  bool
		isLocal   bool
	}{
		{name: "ipv6 ula fc00::1", input: "fc00::1", isPrivate: true},
		{name: "ipv6 ula fd00::1", input: "fd00::1", isPrivate: true},
		{name: "ipv6 link-local fe80::1", input: "fe80::1", linkLocal: true, isPublic: true},
		{name: "ipv6 multicast ff02::1", input: "ff02::1", multicast: true, isPublic: true},
		{name: "ipv4 link-local 169.254.0.5", input: "169.254.0.5", linkLocal: true, isPublic: true},
		{name: "ipv4 multicast 224.0.0.1", input: "224.0.0.1", multicast: true, isPublic: true},
		// Cloud metadata literal stays private.
		{name: "cloud metadata stays private", input: "169.254.169.254", isPrivate: true},
		// Public IPv6.
		{name: "ipv6 public", input: "2001:db8::1", isPublic: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyHost(tt.input)
			if got.IsLinkLocal != tt.linkLocal {
				t.Errorf("IsLinkLocal = %v, want %v", got.IsLinkLocal, tt.linkLocal)
			}
			if got.IsMulticast != tt.multicast {
				t.Errorf("IsMulticast = %v, want %v", got.IsMulticast, tt.multicast)
			}
			if got.IsPrivate != tt.isPrivate {
				t.Errorf("IsPrivate = %v, want %v", got.IsPrivate, tt.isPrivate)
			}
			if got.IsPublic != tt.isPublic {
				t.Errorf("IsPublic = %v, want %v", got.IsPublic, tt.isPublic)
			}
			if got.IsLocal != tt.isLocal {
				t.Errorf("IsLocal = %v, want %v", got.IsLocal, tt.isLocal)
			}
		})
	}
}

func TestHostNodeID(t *testing.T) {
	id := HostNodeID("example.com")
	if !strings.HasPrefix(id, "sha256:") {
		t.Errorf("HostNodeID should have sha256: prefix, got %q", id)
	}
	if len(id) != 71 {
		t.Errorf("HostNodeID length = %d, want 71 (sha256: + 64 hex chars)", len(id))
	}

	id1 := HostNodeID("a.com")
	id2 := HostNodeID("b.com")
	if id1 == id2 {
		t.Error("different hostnames should produce different IDs")
	}

	id3 := HostNodeID("a.com")
	if id1 != id3 {
		t.Error("same hostname should produce same ID")
	}
}

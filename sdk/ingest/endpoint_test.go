package ingest

import (
	"strings"
	"testing"
)

func TestSanitizeHTTPEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		want     string
		valid    bool
		userinfo bool
		query    bool
		fragment bool
	}{
		{
			name: "clean absolute endpoint",
			raw:  " https://mcp.example/api/v1 ",
			want: "https://mcp.example/api/v1", valid: true,
		},
		{
			name: "all sensitive components",
			raw:  "https://alice:s3cret@mcp.example/api?api_key=top-secret#access-token",
			want: "https://mcp.example/api", valid: true,
			userinfo: true, query: true, fragment: true,
		},
		{
			name: "empty query delimiter",
			raw:  "http://mcp.example/api?",
			want: "http://mcp.example/api", valid: true, query: true,
		},
		{
			name: "empty fragment delimiter",
			raw:  "http://mcp.example/api#",
			want: "http://mcp.example/api", valid: true, fragment: true,
		},
		{
			name: "malformed URL",
			raw:  "https://alice:secret@mcp.example/%zz?token=secret",
			want: InvalidHTTPEndpointDisplay,
		},
		{
			name: "relative URL",
			raw:  "/mcp?token=secret",
			want: InvalidHTTPEndpointDisplay,
		},
		{
			name: "non HTTP URL",
			raw:  "file:///tmp/mcp?token=secret",
			want: InvalidHTTPEndpointDisplay,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := SanitizeHTTPEndpoint(test.raw)
			if got.Display != test.want || got.Valid != test.valid ||
				got.UserinfoRedacted != test.userinfo ||
				got.QueryRedacted != test.query ||
				got.FragmentRedacted != test.fragment {
				t.Fatalf("SanitizeHTTPEndpoint(%q) = %+v, want display=%q valid=%v userinfo=%v query=%v fragment=%v",
					test.raw, got, test.want, test.valid, test.userinfo, test.query, test.fragment)
			}
			if strings.Contains(got.Display, "secret") || strings.Contains(got.Display, "alice") ||
				strings.Contains(got.Display, "token=") {
				t.Fatalf("sanitized display leaked credential material: %q", got.Display)
			}
			wantRedacted := !test.valid || test.userinfo || test.query || test.fragment
			if got.Redacted() != wantRedacted {
				t.Fatalf("Redacted() = %v, want %v", got.Redacted(), wantRedacted)
			}
		})
	}
}

func TestHTTPIdentityUsesRawEndpointWhileArtifactDisplayIsSanitized(t *testing.T) {
	raw := "https://alice:s3cret@mcp.example/api?api_key=top-secret#diagnostic"
	identity := ResolveMCPServerIdentity("http", raw)
	wantID := ComputeNodeID("MCPServer", "http", raw)
	if identity.ObjectID != wantID || identity.Scheme != MCPHTTPIdentitySchemeV1 || identity.Version != 1 {
		t.Fatalf("HTTP v1 identity changed: got %+v, want %s", identity, wantID)
	}
	safe := SanitizeHTTPEndpoint(raw)
	if safe.Display != "https://mcp.example/api" || !safe.Redacted() {
		t.Fatalf("unsafe HTTP artifact display: %+v", safe)
	}
	if ComputeMCPServerID("http", safe.Display) == identity.ObjectID {
		t.Fatal("sanitized endpoint unexpectedly reproduced a query/userinfo-sensitive HTTP v1 ID")
	}
}

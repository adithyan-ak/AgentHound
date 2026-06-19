package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestBuildTransportStdio(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "stdio",
		Command:   "echo",
		Args:      []string{"hello"},
		Env:       map[string]string{"FOO": "bar"},
	}

	transport, err := buildTransport(spec, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ct, ok := transport.(*mcpsdk.CommandTransport)
	if !ok {
		t.Fatalf("expected *mcpsdk.CommandTransport, got %T", transport)
	}

	if ct.Command.Path == "" {
		t.Error("command path should be set")
	}

	if len(ct.Command.Args) < 2 || ct.Command.Args[1] != "hello" {
		t.Errorf("expected args to contain 'hello', got %v", ct.Command.Args)
	}

	foundEnv := false
	for _, e := range ct.Command.Env {
		if e == "FOO=bar" {
			foundEnv = true
			break
		}
	}
	if !foundEnv {
		t.Error("expected FOO=bar in command env")
	}
}

func TestBuildTransportStdioMissingCommand(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "stdio",
	}

	_, err := buildTransport(spec, false)
	if err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestBuildTransportHTTP(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "http",
		URL:       "http://localhost:8080/mcp",
	}

	transport, err := buildTransport(spec, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	st, ok := transport.(*mcpsdk.StreamableClientTransport)
	if !ok {
		t.Fatalf("expected *mcpsdk.StreamableClientTransport, got %T", transport)
	}

	if st.Endpoint != "http://localhost:8080/mcp" {
		t.Errorf("expected endpoint http://localhost:8080/mcp, got %s", st.Endpoint)
	}
}

func TestBuildTransportHTTPInsecure(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "http",
		URL:       "https://localhost:8443/mcp",
	}

	transport, err := buildTransport(spec, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	st, ok := transport.(*mcpsdk.StreamableClientTransport)
	if !ok {
		t.Fatalf("expected *mcpsdk.StreamableClientTransport, got %T", transport)
	}

	if st.HTTPClient == nil {
		t.Error("expected custom HTTP client for insecure transport")
	}
}

func TestBuildTransportHTTPWithHeaders(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "http",
		URL:       "http://localhost:8080/mcp",
		Headers:   map[string]string{"Authorization": "Bearer token123"},
	}

	transport, err := buildTransport(spec, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	st, ok := transport.(*mcpsdk.StreamableClientTransport)
	if !ok {
		t.Fatalf("expected *mcpsdk.StreamableClientTransport, got %T", transport)
	}

	if st.HTTPClient == nil {
		t.Error("expected custom HTTP client for transport with headers")
	}
}

func TestBuildTransportHTTPMissingURL(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "http",
	}

	_, err := buildTransport(spec, false)
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestBuildTransportUnsupported(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "grpc",
	}

	_, err := buildTransport(spec, false)
	if err == nil {
		t.Fatal("expected error for unsupported transport")
	}
}

// TestBuildHTTPTransport_TLSStrictDefault verifies that the MCP HTTP transport
// rejects self-signed certificates by default. When the caller passes custom
// headers (forcing the transport to build its own http.Client), insecure=false
// must produce a client that performs full certificate verification.
//
// We probe the underlying *http.Client directly rather than driving the full
// MCP SDK handshake — the test server is plain HTTP, not MCP, so an SDK
// connect would fail for unrelated protocol reasons. The TLS-handshake
// failure path is the same regardless of upstream protocol.
func TestBuildHTTPTransport_TLSStrictDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// insecure=false WITH headers: code path that builds a custom *http.Client.
	spec := ServerSpec{
		Name:      "tls-test",
		Transport: "http",
		URL:       srv.URL,
		Headers:   map[string]string{"X-Test": "1"},
	}
	tr, err := buildTransport(spec, false)
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}
	st, ok := tr.(*mcpsdk.StreamableClientTransport)
	if !ok || st.HTTPClient == nil {
		t.Fatalf("expected custom *http.Client when insecure=false with headers; got %T", tr)
	}
	if _, err := st.HTTPClient.Get(srv.URL); err == nil {
		t.Fatal("expected TLS verification error against self-signed cert; got nil")
	} else if !strings.Contains(err.Error(), "x509") &&
		!strings.Contains(err.Error(), "certificate") &&
		!strings.Contains(err.Error(), "tls") {
		t.Errorf("expected TLS-related error, got: %v", err)
	}

	// insecure=true: same server should now succeed.
	tr, err = buildTransport(spec, true)
	if err != nil {
		t.Fatalf("buildTransport (insecure): %v", err)
	}
	st, _ = tr.(*mcpsdk.StreamableClientTransport)
	if _, err := st.HTTPClient.Get(srv.URL); err != nil {
		t.Errorf("insecure=true against self-signed cert: unexpected error %v", err)
	}
}

// TestHeaderRoundTripper_StripsAuthOnCrossHostRedirect verifies that
// caller-supplied headers (e.g. Authorization) are sent to the original
// endpoint host but NOT carried to a different host on a 302 redirect.
func TestHeaderRoundTripper_StripsAuthOnCrossHostRedirect(t *testing.T) {
	var secondAuth string
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	var firstAuth string
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, second.URL, http.StatusFound)
	}))
	defer first.Close()

	client := &http.Client{Transport: headerRoundTripper{
		base:    &http.Transport{},
		headers: map[string]string{"Authorization": "Bearer secret-token"},
		host:    endpointHost(first.URL),
	}}

	resp, err := client.Get(first.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if firstAuth != "Bearer secret-token" {
		t.Errorf("same-host request: Authorization = %q, want %q", firstAuth, "Bearer secret-token")
	}
	if secondAuth != "" {
		t.Errorf("cross-host redirect leaked Authorization: got %q, want empty", secondAuth)
	}
}

// TestHeaderRoundTripper_SameHostUnchanged verifies that same-host requests
// still receive caller-supplied headers (no regression for the common case).
func TestHeaderRoundTripper_SameHostUnchanged(t *testing.T) {
	var gotAuth, gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: headerRoundTripper{
		base:    &http.Transport{},
		headers: map[string]string{"Authorization": "Bearer tok", "X-Custom": "v"},
		host:    endpointHost(srv.URL),
	}}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
	if gotCustom != "v" {
		t.Errorf("X-Custom = %q, want %q", gotCustom, "v")
	}
}

func TestBuildSSETransport(t *testing.T) {
	spec := ServerSpec{
		Name:      "test-server",
		Transport: "http",
		URL:       "http://localhost:8080/sse",
	}

	transport := buildSSETransport(spec, false)
	_, ok := transport.(*mcpsdk.SSEClientTransport)
	if !ok {
		t.Fatalf("expected *mcpsdk.SSEClientTransport, got %T", transport)
	}
}

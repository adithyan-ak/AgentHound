package mcp

import (
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

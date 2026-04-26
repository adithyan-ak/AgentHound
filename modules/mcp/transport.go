package mcp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type ServerSpec struct {
	Name      string
	Transport string // "stdio" or "http"
	Command   string
	Args      []string
	Env       map[string]string
	URL       string
	Headers   map[string]string
}

func buildTransport(spec ServerSpec, insecure bool) (mcpsdk.Transport, error) {
	switch spec.Transport {
	case "stdio":
		return buildStdioTransport(spec)
	case "http":
		return buildHTTPTransport(spec, insecure)
	default:
		return nil, fmt.Errorf("unsupported transport: %q", spec.Transport)
	}
}

func buildStdioTransport(spec ServerSpec) (mcpsdk.Transport, error) {
	if spec.Command == "" {
		return nil, fmt.Errorf("stdio transport requires a command")
	}

	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = os.Environ()
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	return &mcpsdk.CommandTransport{Command: cmd}, nil
}

func buildHTTPTransport(spec ServerSpec, insecure bool) (mcpsdk.Transport, error) {
	if spec.URL == "" {
		return nil, fmt.Errorf("http transport requires a URL")
	}

	transport := &mcpsdk.StreamableClientTransport{
		Endpoint: spec.URL,
	}

	if insecure || len(spec.Headers) > 0 {
		httpTransport := &http.Transport{}
		if insecure {
			httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		}
		transport.HTTPClient = &http.Client{Transport: headerRoundTripper{
			base:    httpTransport,
			headers: spec.Headers,
		}}
	}

	return transport, nil
}

func buildSSETransport(spec ServerSpec, insecure bool) mcpsdk.Transport {
	transport := &mcpsdk.SSEClientTransport{
		Endpoint: spec.URL,
	}

	if insecure || len(spec.Headers) > 0 {
		httpTransport := &http.Transport{}
		if insecure {
			httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		}
		transport.HTTPClient = &http.Client{Transport: headerRoundTripper{
			base:    httpTransport,
			headers: spec.Headers,
		}}
	}

	return transport
}

type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return h.base.RoundTrip(req)
}

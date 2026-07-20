package mcp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type ServerSpec struct {
	Name            string
	ConfiguredNames []string
	Transport       string // "stdio" or "http"
	Command         string
	Args            []string
	Env             map[string]string
	URL             string
	Headers         map[string]string
	// Configured records that the target came from a real client config. It
	// lets the projection retain configuration-backed claims separately from
	// live initialize evidence.
	Configured bool
	// Ambiguity is a fixed, non-sensitive diagnostic set when multiple
	// execution/auth profiles share this canonical server identity. Such a spec
	// is reported fail-closed and is never used to construct a transport.
	Ambiguity string
}

// canonicalMCPHeaders converts HTTP field names to the exact canonical form
// used by net/http before profile comparison or request construction. JSON
// objects may contain case variants such as "Authorization" and
// "authorization" simultaneously. Header.Set canonicalizes both to the same
// wire field, so retaining distinct values would make Go map iteration choose
// the credential sent on the wire. Equal duplicates are harmless aliases;
// conflicting duplicates must fail before transport.
func canonicalMCPHeaders(headers map[string]string) (map[string]string, bool) {
	canonical := make(map[string]string, len(headers))
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		canonicalName := http.CanonicalHeaderKey(name)
		value := headers[name]
		if existing, present := canonical[canonicalName]; present {
			if existing != value {
				return nil, true
			}
			continue
		}
		canonical[canonicalName] = value
	}
	return canonical, false
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
	canonicalHeaders, conflictingHeaders := canonicalMCPHeaders(spec.Headers)
	if conflictingHeaders {
		return nil, errors.New(ambiguousServerProfileError)
	}
	origin, err := parseMCPHTTPOrigin(spec.URL)
	if err != nil {
		return nil, fmt.Errorf("http transport requires a valid absolute HTTP(S) URL")
	}

	// Enumeration is request/response only. The SDK's optional standalone SSE
	// listener uses a connection-lifetime context detached from Connect; a peer
	// that never completes the GET response headers can therefore outlive the
	// collector's per-server timeout before Connect returns. Disabling that
	// optional listener keeps every enumeration request on the bounded call
	// context while retaining streamable POST responses.
	transport := &mcpsdk.StreamableClientTransport{
		Endpoint:             spec.URL,
		DisableStandaloneSSE: true,
	}

	if insecure || len(canonicalHeaders) > 0 {
		httpTransport := &http.Transport{}
		if insecure {
			httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		}
		transport.HTTPClient = &http.Client{Transport: headerRoundTripper{
			base:    httpTransport,
			headers: canonicalHeaders,
			origin:  origin,
		}}
	}

	return transport, nil
}

func buildSSETransport(spec ServerSpec, insecure bool) mcpsdk.Transport {
	transport := &mcpsdk.SSEClientTransport{
		Endpoint: spec.URL,
	}
	origin, _ := parseMCPHTTPOrigin(spec.URL)

	if insecure || len(spec.Headers) > 0 {
		httpTransport := &http.Transport{}
		if insecure {
			httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		}
		transport.HTTPClient = &http.Client{Transport: headerRoundTripper{
			base:    httpTransport,
			headers: spec.Headers,
			origin:  origin,
		}}
	}

	return transport
}

// withHTTPTransportDeadline carries the collector's absolute per-server
// deadline into SDK-owned HTTP lifecycle requests. The streamable SDK detaches
// its connection context after Connect and sends session cleanup DELETE before
// canceling that detached context, so request contexts alone cannot bound
// cleanup. An absolute transport deadline preserves one total server budget
// without adding a fresh timeout for every request.
func withHTTPTransportDeadline(transport mcpsdk.Transport, deadline time.Time) mcpsdk.Transport {
	wrapClient := func(client *http.Client) *http.Client {
		if client == nil {
			client = http.DefaultClient
		}
		clone := *client
		base := clone.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		clone.Transport = deadlineRoundTripper{base: base, deadline: deadline}
		return &clone
	}

	switch transport := transport.(type) {
	case *mcpsdk.StreamableClientTransport:
		clone := *transport
		clone.HTTPClient = wrapClient(transport.HTTPClient)
		return &clone
	case *mcpsdk.SSEClientTransport:
		clone := *transport
		clone.HTTPClient = wrapClient(transport.HTTPClient)
		return &clone
	default:
		return transport
	}
}

// parseMCPHTTPOrigin derives only the scheme/host/port boundary used to scope
// configured headers. MCP target URLs may legitimately carry userinfo, query,
// or a client-side fragment: those bytes remain identity/transport input but
// must not enter the public origin parser, which intentionally rejects them for
// campaign endpoints. The sanitizer preserves the exact origin while removing
// only components that cannot affect it.
func parseMCPHTTPOrigin(rawURL string) (campaign.HTTPOrigin, error) {
	safeEndpoint := ingest.SanitizeHTTPEndpoint(rawURL)
	if !safeEndpoint.Valid {
		return campaign.HTTPOrigin{}, errors.New("invalid MCP HTTP endpoint")
	}
	return campaign.ParseHTTPOrigin(safeEndpoint.Display)
}

type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
	origin  campaign.HTTPOrigin
}

// RoundTrip injects caller-supplied headers only when the request targets the
// original endpoint host. Go's http.Client strips sensitive headers (e.g.
// Authorization) on cross-host redirects; re-adding them on every request would
// leak credentials to the redirect target. Scoping to the original host
// preserves that protection while keeping same-host behavior unchanged.
func (h headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	canonicalHeaders, conflictingHeaders := canonicalMCPHeaders(h.headers)
	if conflictingHeaders {
		return nil, errors.New(ambiguousServerProfileError)
	}
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	if h.origin.Matches(req.URL) {
		for k, v := range canonicalHeaders {
			cloned.Header.Set(k, v)
		}
	} else {
		for k := range canonicalHeaders {
			cloned.Header.Del(k)
		}
	}
	base := h.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(cloned)
}

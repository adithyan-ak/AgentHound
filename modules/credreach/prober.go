package credreach

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
)

const defaultProbeTimeout = 30 * time.Second

// defaultProber is the live MCP prober used when RunInput.Prober is nil.
func defaultProber() campaign.Prober { return &mcpProber{} }

// mcpProber performs a single read-only resources/read against a streamable
// HTTP MCP server, optionally presenting a bearer credential. It never logs the
// credential and never returns resource content.
type mcpProber struct{}

func (p *mcpProber) Probe(ctx context.Context, req campaign.ProbeRequest) campaign.ProbeResult {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := buildProbeTransport(req)
	client := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "AgentHound", Version: common.CollectorVersion},
		nil,
	)

	session, err := client.Connect(pctx, transport, nil)
	if err != nil {
		return campaign.ProbeResult{
			Status: classifyProbeError(pctx, err),
			Detail: sanitizeDetail(err),
		}
	}
	defer session.Close()

	if _, err := session.ReadResource(pctx, &mcpsdk.ReadResourceParams{URI: req.ResourceURI}); err != nil {
		return campaign.ProbeResult{
			Status: classifyProbeError(pctx, err),
			Detail: sanitizeDetail(err),
		}
	}
	return campaign.ProbeResult{Status: campaign.ProbeAllowed, Detail: "read succeeded"}
}

// buildProbeTransport builds a streamable HTTP transport. The authed probe adds
// an Authorization: Bearer header scoped to the endpoint host so redirects can
// never leak the credential to a third-party host. TLS verification stays on
// unless the operator opted into --insecure.
func buildProbeTransport(req campaign.ProbeRequest) mcpsdk.Transport {
	transport := &mcpsdk.StreamableClientTransport{Endpoint: req.Host}

	headers := map[string]string{}
	if strings.TrimSpace(req.Credential) != "" {
		headers["Authorization"] = "Bearer " + req.Credential
	}
	if req.Insecure || len(headers) > 0 {
		httpTransport := &http.Transport{}
		if req.Insecure {
			httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		}
		transport.HTTPClient = &http.Client{Transport: probeHeaderRoundTripper{
			base:    httpTransport,
			headers: headers,
			host:    endpointHost(req.Host),
		}}
	}
	return transport
}

// probeHeaderRoundTripper injects headers only for requests to the original
// endpoint host. This mirrors modules/mcp's transport: Go strips sensitive
// headers on cross-host redirects, and re-adding them on every request would
// leak the credential to the redirect target.
type probeHeaderRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
	host    string
}

func (h probeHeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if h.host == "" || req.URL.Host == h.host {
		for k, v := range h.headers {
			req.Header.Set(k, v)
		}
	}
	return h.base.RoundTrip(req)
}

func endpointHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Host
}

// classifyProbeError maps a connect/read error to a ProbeStatus conservatively.
// Structured MCP/JSON-RPC codes are preferred; otherwise the message is
// inspected. Anything it cannot map cleanly becomes ProbeAmbiguous so an
// uncertain result never collapses to a definitive not_observed.
func classifyProbeError(ctx context.Context, err error) campaign.ProbeStatus {
	if err == nil {
		return campaign.ProbeAllowed
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		(ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return campaign.ProbeTimeout
	}
	if status, ok := classifyStructuredError(err); ok {
		return status
	}
	return classifyErrorMessage(err.Error())
}

// classifyStructuredError inspects any MCP/JSON-RPC WireError in the chain.
func classifyStructuredError(err error) (campaign.ProbeStatus, bool) {
	var wire *jsonrpc.Error
	if !errors.As(err, &wire) {
		return "", false
	}
	switch wire.Code {
	case mcpsdk.CodeResourceNotFound:
		return campaign.ProbeNotFound, true
	case mcpsdk.CodeHeaderMismatch:
		return campaign.ProbeMalformedAuth, true
	default:
		// A structured error with an auth-flavored message is a denial; other
		// codes fall through to message inspection for HTTP-status hints.
		if isAuthDenial(strings.ToLower(wire.Message)) {
			return campaign.ProbeDenied, true
		}
		return "", false
	}
}

func classifyErrorMessage(raw string) campaign.ProbeStatus {
	msg := strings.ToLower(raw)
	switch {
	case isAuthDenial(msg):
		return campaign.ProbeDenied
	case containsAny(msg, "404", "not found", "resource not found", "no such resource"):
		return campaign.ProbeNotFound
	case containsAny(msg, "400", "bad request", "malformed"):
		return campaign.ProbeMalformedAuth
	case containsAny(msg, "timeout", "timed out", "deadline exceeded"):
		return campaign.ProbeTimeout
	case containsAny(msg, "connection refused", "no such host", "connection reset", "eof", "tls", "certificate"):
		return campaign.ProbeError
	case containsAny(msg, "parse error", "protocol", "json-rpc", "jsonrpc", "invalid message"):
		return campaign.ProbeProtocolError
	default:
		return campaign.ProbeAmbiguous
	}
}

func isAuthDenial(msg string) bool {
	return containsAny(msg, "401", "403", "unauthorized", "forbidden", "permission denied", "access denied")
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// sanitizeDetail returns a short, non-sensitive diagnostic. Errors describe a
// failure, not resource content, and the credential is never placed in a
// request error — but Detail is bounded and never persisted into evidence.
func sanitizeDetail(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	const max = 200
	if len(msg) > max {
		return msg[:max] + "…"
	}
	return msg
}

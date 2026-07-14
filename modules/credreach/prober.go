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

	deadline, _ := pctx.Deadline()
	transport := buildProbeTransport(req, deadline)
	client := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "AgentHound", Version: common.CollectorVersion},
		nil,
	)

	session, err := client.Connect(pctx, transport, nil)
	if err != nil {
		status := classifyProbeError(pctx, err)
		return campaign.ProbeResult{
			Stage:  campaign.ProbeStageInitialize,
			Status: status,
			Detail: probeDetailCode(campaign.ProbeStageInitialize, status),
		}
	}
	defer func() { _ = session.Close() }()

	if _, err := session.ReadResource(pctx, &mcpsdk.ReadResourceParams{URI: req.ResourceURI}); err != nil {
		status := classifyProbeError(pctx, err)
		return campaign.ProbeResult{
			Stage:             campaign.ProbeStageResourceRead,
			ResourceAddressed: true,
			Status:            status,
			Detail:            probeDetailCode(campaign.ProbeStageResourceRead, status),
		}
	}
	return campaign.ProbeResult{
		Stage:             campaign.ProbeStageResourceRead,
		ResourceAddressed: true,
		Status:            campaign.ProbeAllowed,
		Detail:            "resource_read_allowed",
	}
}

// buildProbeTransport builds a streamable HTTP transport. The authed probe adds
// an Authorization: Bearer header scoped to the endpoint's exact origin so
// redirects cannot leak the credential across scheme, hostname, or effective
// port. TLS verification stays on unless the operator opted into --insecure.
func buildProbeTransport(req campaign.ProbeRequest, deadline time.Time) mcpsdk.Transport {
	transport := &mcpsdk.StreamableClientTransport{Endpoint: req.Host}
	origin, _ := campaign.ParseHTTPOrigin(req.Host)
	endpoint, _ := url.Parse(req.Host)

	headers := map[string]string{}
	if strings.TrimSpace(req.Credential) != "" {
		headers["Authorization"] = "Bearer " + req.Credential
	}
	httpTransport := &http.Transport{}
	if req.Insecure {
		httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	var base http.RoundTripper = httpTransport
	if len(headers) > 0 {
		base = probeHeaderRoundTripper{
			base:    httpTransport,
			headers: headers,
			origin:  origin,
		}
	}
	base = observedHTTPStatusRoundTripper{base: base}
	base = campaign.CountingTransport{Base: base}
	transport.HTTPClient = &http.Client{Transport: endpointDeleteDeadlineRoundTripper{
		base:     base,
		endpoint: endpoint,
		deadline: deadline,
	}}
	return transport
}

// observedHTTPStatusError preserves a status actually returned by the target.
// Error text alone is never sufficient to establish a definitive auth denial.
type observedHTTPStatusError struct {
	statusCode int
}

func (e *observedHTTPStatusError) Error() string {
	return "observed HTTP response: " + http.StatusText(e.statusCode)
}

// observedHTTPStatusRoundTripper converts only observed 401/403 responses into
// typed errors before the MCP SDK flattens their status into error text.
type observedHTTPStatusRoundTripper struct {
	base http.RoundTripper
}

func (t observedHTTPStatusRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return resp, nil
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	return nil, &observedHTTPStatusError{statusCode: resp.StatusCode}
}

// endpointDeleteDeadlineRoundTripper restores the original absolute scenario
// deadline only for the MCP SDK's exact-endpoint DELETE. The SDK intentionally
// detaches its connection context, so Close would otherwise be unbounded. This
// wrapper is outside CountingTransport: a DELETE dispatched before the deadline
// is counted even when the target hangs until that deadline.
type endpointDeleteDeadlineRoundTripper struct {
	base     http.RoundTripper
	endpoint *url.URL
	deadline time.Time
}

func (t endpointDeleteDeadlineRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Method != http.MethodDelete || !sameEndpoint(req.URL, t.endpoint) || t.deadline.IsZero() {
		return base.RoundTrip(req)
	}
	ctx, cancel := context.WithDeadline(req.Context(), t.deadline)
	defer cancel()
	return base.RoundTrip(req.Clone(ctx))
}

func sameEndpoint(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		left.Host == right.Host &&
		left.EscapedPath() == right.EscapedPath() &&
		left.RawQuery == right.RawQuery &&
		left.ForceQuery == right.ForceQuery
}

// probeHeaderRoundTripper injects headers only for requests to the original
// endpoint host. This mirrors modules/mcp's transport: Go strips sensitive
// headers on cross-host redirects, and re-adding them on every request would
// leak the credential to the redirect target.
type probeHeaderRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
	origin  campaign.HTTPOrigin
}

func (h probeHeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	if h.origin.Matches(req.URL) {
		for k, v := range h.headers {
			cloned.Header.Set(k, v)
		}
	} else {
		for k := range h.headers {
			cloned.Header.Del(k)
		}
	}
	base := h.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(cloned)
}

// classifyProbeError maps a connect/read error to a ProbeStatus conservatively.
// Only a typed HTTP response observed by observedHTTPStatusRoundTripper can
// establish a 401/403 denial. Structured non-auth MCP codes and conservative
// non-denial diagnostics remain classified; unknowns are ambiguous.
func classifyProbeError(ctx context.Context, err error) campaign.ProbeStatus {
	if err == nil {
		return campaign.ProbeAllowed
	}
	var observed *observedHTTPStatusError
	if errors.As(err, &observed) &&
		(observed.statusCode == http.StatusUnauthorized ||
			observed.statusCode == http.StatusForbidden) {
		return campaign.ProbeDenied
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
		return "", false
	}
}

func classifyErrorMessage(raw string) campaign.ProbeStatus {
	msg := strings.ToLower(raw)
	switch {
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

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func probeDetailCode(stage campaign.ProbeStage, status campaign.ProbeStatus) string {
	return string(stage) + "_" + string(status)
}

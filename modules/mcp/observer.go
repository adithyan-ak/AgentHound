package mcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
)

const defaultObserverResponseBytes int64 = 1 << 20

// ToolObservation is one exact tool projection returned by an initialized MCP
// session after the SDK has exhausted tools/list pagination.
type ToolObservation struct {
	Name        string
	Description string
}

// ToolObserver provides the lifecycle-correct read primitive used by MCP
// metadata management adapters.
type ToolObserver struct {
	InitTimeout      time.Duration
	MaxItems         int
	MaxResponseBytes int64
	Insecure         bool
	RejectRedirects  bool
}

// Observe initializes an MCP session, verifies the tools capability, exhausts
// tools/list pagination through the official SDK, and returns exactly one tool.
func (o ToolObserver) Observe(ctx context.Context, spec ServerSpec, toolName string) (ToolObservation, error) {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return ToolObservation{}, errors.New("mcp tool observer: tool name is required")
	}
	if o.InitTimeout <= 0 {
		o.InitTimeout = 30 * time.Second
	}
	if o.MaxItems <= 0 {
		o.MaxItems = defaultMaxItems
	}
	if o.MaxResponseBytes <= 0 {
		o.MaxResponseBytes = defaultObserverResponseBytes
	}

	observeCtx, cancel := context.WithTimeout(ctx, o.InitTimeout)
	defer cancel()

	deadline, _ := observeCtx.Deadline()
	transport, err := o.transport(spec, deadline)
	if err != nil {
		return ToolObservation{}, safeToolObserverError("transport setup", err)
	}
	session, err := o.connect(observeCtx, transport)
	if err != nil {
		return ToolObservation{}, safeToolObserverError("initialize", err)
	}
	defer func() { _ = session.Close() }()

	initResult := session.InitializeResult()
	if initResult == nil || initResult.Capabilities == nil || initResult.Capabilities.Tools == nil {
		return ToolObservation{}, errors.New("mcp tool observer: initialized server did not advertise tools capability")
	}
	var observed ToolObservation
	found := false
	items := 0
	for tool, iterErr := range session.Tools(observeCtx, nil) {
		if iterErr != nil {
			return ToolObservation{}, safeToolObserverError("tools/list", iterErr)
		}
		if items >= o.MaxItems {
			return ToolObservation{}, fmt.Errorf("mcp tool observer: tools/list exceeded safety limit of %d items", o.MaxItems)
		}
		items++
		if tool == nil || tool.Name != toolName {
			continue
		}
		if found {
			return ToolObservation{}, fmt.Errorf("mcp tool observer: tool name %q is not unique", toolName)
		}
		found = true
		observed = ToolObservation{Name: tool.Name, Description: tool.Description}
	}
	if !found {
		return ToolObservation{}, fmt.Errorf("mcp tool observer: tool %q not found", toolName)
	}
	return observed, nil
}

// safeToolObserverError deliberately drops arbitrary transport and protocol
// error text because SDK errors can echo target URLs, credentials, or remote
// JSON-RPC messages. The two standard context sentinels are preserved without
// retaining any of the surrounding, potentially sensitive error chain.
func safeToolObserverError(stage string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("mcp tool observer: %s failed: %w", stage, context.DeadlineExceeded)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("mcp tool observer: %s failed: %w", stage, context.Canceled)
	default:
		return fmt.Errorf("mcp tool observer: %s failed; details omitted", stage)
	}
}

func (o ToolObserver) connect(ctx context.Context, transport mcpsdk.Transport) (*mcpsdk.ClientSession, error) {
	client := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "AgentHound", Version: common.CollectorVersion()},
		nil,
	)
	initCtx, cancel := context.WithTimeout(ctx, o.InitTimeout)
	defer cancel()
	return client.Connect(initCtx, transport, nil)
}

func (o ToolObserver) transport(spec ServerSpec, deadline time.Time) (mcpsdk.Transport, error) {
	if spec.Transport != "http" {
		return buildTransport(spec, o.Insecure)
	}
	origin, err := campaign.ParseHTTPOrigin(spec.URL)
	if err != nil {
		return nil, errors.New("http transport requires a valid absolute HTTP(S) URL")
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not configurable")
	}
	base := defaultTransport.Clone()
	if o.Insecure {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		} else {
			base.TLSClientConfig = base.TLSClientConfig.Clone()
		}
		base.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
	}
	client := &http.Client{
		Timeout: o.InitTimeout,
		Transport: deadlineRoundTripper{deadline: deadline, base: headerRoundTripper{
			base: boundedResponseRoundTripper{
				base: campaign.CountingTransport{Base: base},
				max:  o.MaxResponseBytes,
			},
			headers: spec.Headers,
			origin:  origin,
		}},
	}
	if o.RejectRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return errors.New("MCP redirect rejected")
		}
	}
	return &mcpsdk.StreamableClientTransport{
		Endpoint:             spec.URL,
		HTTPClient:           client,
		DisableStandaloneSSE: true,
	}, nil
}

type deadlineRoundTripper struct {
	base     http.RoundTripper
	deadline time.Time
}

func (t deadlineRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if existing, ok := ctx.Deadline(); ok && !t.deadline.Before(existing) {
		return t.base.RoundTrip(req)
	}
	bounded, cancel := context.WithDeadline(ctx, t.deadline)
	cloned := req.Clone(bounded)
	resp, err := t.base.RoundTrip(cloned)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelReadCloser{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel()
	return err
}

func observeSessionTools(
	ctx context.Context,
	session *mcpsdk.ClientSession,
	maxItems int,
) (tools []*mcpsdk.Tool, truncated bool, err error) {
	if maxItems <= 0 {
		maxItems = defaultMaxItems
	}
	for tool, iterErr := range session.Tools(ctx, nil) {
		if iterErr != nil {
			return tools, false, iterErr
		}
		if len(tools) >= maxItems {
			return tools, true, nil
		}
		tools = append(tools, tool)
	}
	return tools, false, nil
}

type boundedResponseRoundTripper struct {
	base http.RoundTripper
	max  int64
}

func (t boundedResponseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &boundedReadCloser{reader: resp.Body, closer: resp.Body, remaining: t.max}
	return resp, nil
}

type boundedReadCloser struct {
	reader    io.Reader
	closer    io.Closer
	remaining int64
}

func (r *boundedReadCloser) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			return 0, errors.New("MCP response exceeded size limit")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func (r *boundedReadCloser) Close() error { return r.closer.Close() }

package credreach

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

func TestClassifyStructuredErrors(t *testing.T) {
	notFound := &jsonrpc.Error{Code: mcpsdk.CodeResourceNotFound, Message: "resource not found"}
	if got := classifyProbeError(context.Background(), notFound); got != campaign.ProbeNotFound {
		t.Fatalf("resource-not-found code => %q, want not_found", got)
	}
	headerMismatch := &jsonrpc.Error{Code: mcpsdk.CodeHeaderMismatch, Message: "bad headers"}
	if got := classifyProbeError(context.Background(), headerMismatch); got != campaign.ProbeMalformedAuth {
		t.Fatalf("header-mismatch code => %q, want malformed_auth", got)
	}
	authWire := &jsonrpc.Error{Code: -32000, Message: "Unauthorized"}
	if got := classifyProbeError(context.Background(), authWire); got != campaign.ProbeAmbiguous {
		t.Fatalf("unauthorized wire message => %q, want ambiguous", got)
	}
}

func TestClassifyErrorMessages(t *testing.T) {
	cases := []struct {
		msg  string
		want campaign.ProbeStatus
	}{
		{"http 401 Unauthorized", campaign.ProbeAmbiguous},
		{"received 403 Forbidden", campaign.ProbeAmbiguous},
		{"permission denied by policy", campaign.ProbeAmbiguous},
		{"access denied: credential rejected", campaign.ProbeAmbiguous},
		{"server returned 404 Not Found", campaign.ProbeNotFound},
		{"resource not found on server", campaign.ProbeNotFound},
		{"400 Bad Request: malformed header", campaign.ProbeMalformedAuth},
		{"connection refused", campaign.ProbeError},
		{"x509: certificate signed by unknown authority", campaign.ProbeError},
		{"json-rpc parse error", campaign.ProbeProtocolError},
		{"something totally unexpected", campaign.ProbeAmbiguous},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			if got := classifyProbeError(context.Background(), errors.New(tc.msg)); got != tc.want {
				t.Fatalf("classify(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

func TestOnlyTypedObservedHTTPAuthStatusIsDenied(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		err := fmt.Errorf("wrapped transport failure: %w", &observedHTTPStatusError{statusCode: status})
		if got := classifyProbeError(context.Background(), err); got != campaign.ProbeDenied {
			t.Fatalf("typed observed HTTP %d => %q, want denied", status, got)
		}
	}

	for _, wire := range []*jsonrpc.Error{
		{Code: -32100, Message: "HTTP 401 Unauthorized"},
		{Code: -32101, Message: "403 Forbidden"},
		{Code: -32102, Message: "permission denied"},
	} {
		if got := classifyProbeError(context.Background(), wire); got != campaign.ProbeAmbiguous {
			t.Errorf("JSON-RPC code %d message %q => %q, want ambiguous", wire.Code, wire.Message, got)
		}
	}
}

func TestObservedHTTPAuthResponseIsDenied(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()

			result := (&mcpProber{}).Probe(context.Background(), campaign.ProbeRequest{
				Host: srv.URL, ResourceURI: "test://resource", Timeout: time.Second,
			})
			if result.Stage != campaign.ProbeStageInitialize || result.Status != campaign.ProbeDenied {
				t.Fatalf("probe result = %+v, want typed initialize denial", result)
			}
		})
	}
}

func TestClassifyTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classifyProbeError(context.Background(), context.DeadlineExceeded); got != campaign.ProbeTimeout {
		t.Fatalf("deadline error => %q, want timeout", got)
	}
	_ = ctx
}

// TestNotFoundStaysIndeterminate ties the prober classification to the matrix:
// a control-denied + authed-404 pair must never collapse to not_observed.
func TestNotFoundStaysIndeterminate(t *testing.T) {
	authed404 := classifyProbeError(context.Background(),
		&jsonrpc.Error{Code: mcpsdk.CodeResourceNotFound, Message: "missing"})
	control := campaign.ProbeResult{
		Stage:             campaign.ProbeStageResourceRead,
		ResourceAddressed: true,
		Status:            campaign.ProbeDenied,
	}
	authed := campaign.ProbeResult{
		Stage:             campaign.ProbeStageResourceRead,
		ResourceAddressed: true,
		Status:            authed404,
	}
	if got := campaign.Classify(control, authed); got != campaign.OutcomeIndeterminate {
		t.Fatalf("denied + 404 => %q, want indeterminate", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDeleteDeadlineAppliesOnlyToExactEndpoint(t *testing.T) {
	endpoint, err := url.Parse("https://example.test/mcp?tenant=one")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	var observed time.Time
	rt := endpointDeleteDeadlineRoundTripper{
		endpoint: endpoint,
		deadline: deadline,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			observed, _ = req.Context().Deadline()
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
	}
	cases := []struct {
		name         string
		method       string
		target       string
		wantDeadline bool
	}{
		{"exact DELETE", http.MethodDelete, endpoint.String(), true},
		{"same-origin other path", http.MethodDelete, "https://example.test/other?tenant=one", false},
		{"exact POST", http.MethodPost, endpoint.String(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observed = time.Time{}
			req, err := http.NewRequestWithContext(context.Background(), tc.method, tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if tc.wantDeadline && !observed.Equal(deadline) {
				t.Fatalf("deadline = %v, want original absolute %v", observed, deadline)
			}
			if !tc.wantDeadline && !observed.IsZero() {
				t.Fatalf("unrelated request inherited close deadline %v", observed)
			}
		})
	}
}

func TestMCPProbeHangingCloseUsesOriginalDeadlineAndIsCounted(t *testing.T) {
	const resourceURI = "test://resource"
	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "deadline-test", Version: "1.0.0"},
		nil,
	)
	server.AddResource(
		&mcpsdk.Resource{URI: resourceURI, Name: "resource"},
		func(_ context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
			return &mcpsdk.ReadResourceResult{Contents: []*mcpsdk.ResourceContents{{
				URI: req.Params.URI, Text: "redacted",
			}}}, nil
		},
	)
	mcpHandler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)

	type deleteObservation struct {
		ordinal int32
		counted int
	}
	deleteSeen := make(chan deleteObservation, 1)
	var requests atomic.Int32
	var budget *campaign.Budget
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ordinal := requests.Add(1)
		if r.Method == http.MethodDelete {
			deleteSeen <- deleteObservation{
				ordinal: ordinal,
				counted: budget.Snapshot().RequestsUsed,
			}
			<-r.Context().Done()
			return
		}
		mcpHandler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	runCtx, cancel, runBudget := campaign.NewBudgetContext(context.Background(), campaign.RunLimits{
		RequestLimit: 16, ElapsedLimit: 2 * time.Second,
	})
	defer cancel()
	budget = runBudget

	resultCh := make(chan campaign.ProbeResult, 1)
	started := time.Now()
	go func() {
		resultCh <- (&mcpProber{}).Probe(runCtx, campaign.ProbeRequest{
			Host: httpServer.URL, ResourceURI: resourceURI, Timeout: 200 * time.Millisecond,
		})
	}()

	var result campaign.ProbeResult
	select {
	case result = <-resultCh:
	case <-time.After(2 * time.Second):
		httpServer.CloseClientConnections()
		t.Fatal("MCP probe hung in session Close DELETE")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("hanging close returned after %s, want bounded by original deadline", elapsed)
	}
	if result.Status != campaign.ProbeAllowed {
		t.Fatalf("resource probe result = %+v, want allowed before bounded close", result)
	}
	select {
	case observed := <-deleteSeen:
		if observed.counted < int(observed.ordinal) {
			t.Fatalf("DELETE ordinal %d saw requests_used=%d; timed-out close was not counted", observed.ordinal, observed.counted)
		}
	default:
		t.Fatal("MCP SDK Close did not dispatch DELETE")
	}
}

func TestProbeHeaderRoundTripperExactOrigin(t *testing.T) {
	origin, err := campaign.ParseHTTPOrigin("https://Example.COM/mcp")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		target   *url.URL
		wantAuth bool
	}{
		{"same origin", &url.URL{Scheme: "https", Host: "example.com", Path: "/redirected"}, true},
		{"explicit default port", &url.URL{Scheme: "https", Host: "example.com:443", Path: "/redirected"}, true},
		{"scheme downgrade", &url.URL{Scheme: "http", Host: "example.com", Path: "/redirected"}, false},
		{"port change", &url.URL{Scheme: "https", Host: "example.com:444", Path: "/redirected"}, false},
		{"cross host", &url.URL{Scheme: "https", Host: "other.example", Path: "/redirected"}, false},
		{"authority-less", &url.URL{Scheme: "https", Path: "/redirected"}, false},
		{"malformed authority", &url.URL{Scheme: "https", Host: "[::1", Path: "/redirected"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAuth := ""
			rt := probeHeaderRoundTripper{
				origin:  origin,
				headers: map[string]string{"Authorization": "Bearer campaign-secret"},
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					gotAuth = req.Header.Get("Authorization")
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       http.NoBody,
						Request:    req,
					}, nil
				}),
			}
			req := &http.Request{
				Method: http.MethodGet,
				URL:    tc.target,
				Header: http.Header{"Authorization": []string{"Bearer preexisting"}},
			}
			if _, err := rt.RoundTrip(req); err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			if tc.wantAuth && gotAuth != "Bearer campaign-secret" {
				t.Fatalf("Authorization = %q, want campaign header", gotAuth)
			}
			if !tc.wantAuth && gotAuth != "" {
				t.Fatalf("credential leaked to non-matching origin: %q", gotAuth)
			}
		})
	}
}

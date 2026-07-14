package credreach

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

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
	if got := classifyProbeError(context.Background(), authWire); got != campaign.ProbeDenied {
		t.Fatalf("unauthorized wire message => %q, want denied", got)
	}
}

func TestClassifyErrorMessages(t *testing.T) {
	cases := []struct {
		msg  string
		want campaign.ProbeStatus
	}{
		{"http 401 Unauthorized", campaign.ProbeDenied},
		{"received 403 Forbidden", campaign.ProbeDenied},
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

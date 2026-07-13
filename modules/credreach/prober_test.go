package credreach

import (
	"context"
	"errors"
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
	if got := campaign.Classify(campaign.ProbeDenied, authed404); got != campaign.OutcomeIndeterminate {
		t.Fatalf("denied + 404 => %q, want indeterminate", got)
	}
}

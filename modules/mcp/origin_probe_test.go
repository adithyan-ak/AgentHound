package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/contact"
)

const testOriginProbeID = "agenthound-origin-test"

func TestProbeInvalidOriginAgainstStreamableHTTPServer(t *testing.T) {
	tests := []struct {
		name       string
		protection *http.CrossOriginProtection
		want       OriginValidationOutcome
	}{
		{name: "unprotected", want: OriginValidationAccepted},
		{name: "protected", protection: &http.CrossOriginProtection{}, want: OriginValidationRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "origin-fixture", Version: "1"}, nil)
			httpServer := httptest.NewServer(mcpsdk.NewStreamableHTTPHandler(
				func(*http.Request) *mcpsdk.Server { return server },
				&mcpsdk.StreamableHTTPOptions{
					Stateless: true, JSONResponse: true, CrossOriginProtection: test.protection,
				},
			))
			defer httpServer.Close()

			got, err := ProbeInvalidOrigin(
				context.Background(), httpServer.URL, "2025-11-25",
				testOriginProbeID, false, time.Second,
			)
			if err != nil {
				t.Fatalf("ProbeInvalidOrigin: %v", err)
			}
			if got.Outcome != test.want {
				t.Fatalf("result = %+v, want outcome %q", got, test.want)
			}
		})
	}
}

func TestProbeInvalidOriginClassifiesDeterministicResponses(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		contentType  string
		wantOutcome  OriginValidationOutcome
		wantEvidence string
	}{
		{
			name: "403 rejection", status: http.StatusForbidden,
			wantOutcome: OriginValidationRejected, wantEvidence: "http_403",
		},
		{
			name: "matching JSON-RPC result", status: http.StatusOK,
			body:        `{"jsonrpc":"2.0","id":"agenthound-origin-test","result":{}}`,
			contentType: "application/json",
			wantOutcome: OriginValidationAccepted, wantEvidence: "matching_jsonrpc_response",
		},
		{
			name: "matching SSE JSON-RPC error", status: http.StatusOK,
			body:        "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"agenthound-origin-test\",\"error\":{\"code\":-32000}}\n\n",
			contentType: "text/event-stream",
			wantOutcome: OriginValidationAccepted, wantEvidence: "matching_jsonrpc_response",
		},
		{
			name: "authentication ambiguity", status: http.StatusUnauthorized,
			body:        `{"error":"authentication required"}`,
			contentType: "application/json",
			wantOutcome: OriginValidationIndeterminate,
		},
		{
			name: "proxy ambiguity", status: http.StatusBadGateway,
			body: "upstream unavailable", contentType: "text/plain",
			wantOutcome: OriginValidationIndeterminate,
		},
		{
			name: "nonmatching JSON-RPC response", status: http.StatusOK,
			body:        `{"jsonrpc":"2.0","id":"another-request","result":{}}`,
			contentType: "application/json",
			wantOutcome: OriginValidationIndeterminate,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Origin") != InvalidOriginProbeValue {
					t.Errorf("request = %s Origin %q", r.Method, r.Header.Get("Origin"))
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Mcp-Session-Id") != "" {
					t.Error("side-effect-free anonymous probe sent authentication or session state")
				}
				var request struct {
					JSONRPC string `json:"jsonrpc"`
					ID      string `json:"id"`
					Method  string `json:"method"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode request: %v", err)
				}
				if request.JSONRPC != "2.0" || request.ID != testOriginProbeID || request.Method != "ping" {
					t.Errorf("request = %+v", request)
				}
				if test.contentType != "" {
					w.Header().Set("Content-Type", test.contentType)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			got, err := ProbeInvalidOrigin(
				context.Background(), server.URL, "2025-11-25",
				testOriginProbeID, false, time.Second,
			)
			if err != nil {
				t.Fatalf("ProbeInvalidOrigin: %v", err)
			}
			if got.Outcome != test.wantOutcome || got.Evidence != test.wantEvidence ||
				got.HTTPStatus != test.status || got.CleanupStatus != "not_applicable" {
				t.Fatalf("result = %+v, want outcome=%q evidence=%q status=%d", got, test.wantOutcome, test.wantEvidence, test.status)
			}
		})
	}
}

func TestProbeInvalidOriginCleansUnexpectedSessionWithoutOrigin(t *testing.T) {
	const sessionID = "opaque-session-value"
	var deleted atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Mcp-Session-Id", sessionID)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"agenthound-origin-test","result":{}}`))
		case http.MethodDelete:
			if r.Header.Get("Origin") != "" {
				t.Errorf("cleanup Origin = %q, want absent", r.Header.Get("Origin"))
			}
			if r.Header.Get("Mcp-Session-Id") != sessionID {
				t.Errorf("cleanup session = %q", r.Header.Get("Mcp-Session-Id"))
			}
			deleted.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	got, err := ProbeInvalidOrigin(
		context.Background(), server.URL, "2025-11-25",
		testOriginProbeID, false, time.Second,
	)
	if err != nil {
		t.Fatalf("ProbeInvalidOrigin: %v", err)
	}
	if got.Outcome != OriginValidationAccepted || got.Evidence != "session_allocated" ||
		got.CleanupStatus != "restored" || !deleted.Load() {
		t.Fatalf("result = %+v, deleted=%v", got, deleted.Load())
	}
}

func TestProbeInvalidOriginDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusFound)
	}))
	defer source.Close()

	got, err := ProbeInvalidOrigin(
		context.Background(), source.URL, "2025-11-25",
		testOriginProbeID, false, time.Second,
	)
	if err != nil {
		t.Fatalf("ProbeInvalidOrigin: %v", err)
	}
	if got.Outcome != OriginValidationIndeterminate || got.HTTPStatus != http.StatusFound {
		t.Fatalf("result = %+v", got)
	}
	if redirected.Load() != 0 {
		t.Fatal("Origin probe followed a redirect")
	}
}

func TestProbeInvalidOriginHonorsContactPolicy(t *testing.T) {
	var contacted atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		contacted.Store(true)
	}))
	defer server.Close()
	policy, err := contact.NewPolicy([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ProbeInvalidOrigin(
		contact.WithPolicy(context.Background(), policy), server.URL, "2025-11-25",
		testOriginProbeID, false, time.Second,
	)
	if !errors.Is(err, contact.ErrExcluded) {
		t.Fatalf("error = %v, want ErrExcluded", err)
	}
	if contacted.Load() {
		t.Fatal("excluded endpoint was contacted")
	}
}

func TestProbeInvalidOriginBoundsTimeoutAndResponse(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		_, err := ProbeInvalidOrigin(
			context.Background(), server.URL, "2025-11-25",
			testOriginProbeID, false, 20*time.Millisecond,
		)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want deadline exceeded", err)
		}
	})

	t.Run("response size", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", originProbeMaxBodyBytes+1)))
		}))
		defer server.Close()
		_, err := ProbeInvalidOrigin(
			context.Background(), server.URL, "2025-11-25",
			testOriginProbeID, false, time.Second,
		)
		if err == nil || !strings.Contains(err.Error(), "exceeded") {
			t.Fatalf("error = %v, want bounded response error", err)
		}
	})
}

func TestProbeInvalidOriginKeepsTLSStrictByDefault(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"agenthound-origin-test","result":{}}`))
	}))
	defer server.Close()

	if _, err := ProbeInvalidOrigin(
		context.Background(), server.URL, "2025-11-25",
		testOriginProbeID, false, time.Second,
	); err == nil {
		t.Fatal("strict TLS accepted an untrusted test certificate")
	}
	got, err := ProbeInvalidOrigin(
		context.Background(), server.URL, "2025-11-25",
		testOriginProbeID, true, time.Second,
	)
	if err != nil || got.Outcome != OriginValidationAccepted {
		t.Fatalf("insecure probe = %+v, err=%v", got, err)
	}
}

package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/contact"
)

const (
	InvalidOriginProbeValue = "https://agenthound.invalid"
	originProbeMaxBodyBytes = 64 << 10
)

type OriginValidationOutcome string

const (
	OriginValidationRejected      OriginValidationOutcome = "rejected"
	OriginValidationAccepted      OriginValidationOutcome = "accepted"
	OriginValidationIndeterminate OriginValidationOutcome = "indeterminate"
)

type OriginValidationResult struct {
	Outcome       OriginValidationOutcome
	HTTPStatus    int
	Evidence      string
	CleanupStatus string
}

// ProbeInvalidOrigin sends a side-effect-free MCP ping with a deliberately
// invalid Origin. A matching JSON-RPC response proves the MCP endpoint
// processed the request; other non-403 responses remain indeterminate.
func ProbeInvalidOrigin(
	ctx context.Context,
	endpoint string,
	protocolVersion string,
	requestID string,
	insecure bool,
	timeout time.Duration,
) (OriginValidationResult, error) {
	result := OriginValidationResult{
		Outcome:       OriginValidationIndeterminate,
		CleanupStatus: "not_applicable",
	}
	origin, err := parseMCPHTTPOrigin(endpoint)
	if err != nil {
		return result, errors.New("MCP Origin probe requires a valid HTTP(S) endpoint")
	}
	if strings.TrimSpace(requestID) == "" {
		return result, errors.New("MCP Origin probe request ID is required")
	}

	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "ping",
	})
	if err != nil {
		return result, errors.New("MCP Origin probe could not encode its request")
	}

	probeCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	httpTransport := contact.HTTPTransport(nil)
	if insecure {
		httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	client := &http.Client{
		Transport: contact.RoundTripper{Base: headerRoundTripper{
			base: httpTransport, origin: origin,
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(
		probeCtx, http.MethodPost, endpoint, bytes.NewReader(requestBody),
	)
	if err != nil {
		return result, errors.New("MCP Origin probe could not construct its request")
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", InvalidOriginProbeValue)
	if version := strings.TrimSpace(protocolVersion); version != "" {
		request.Header.Set("MCP-Protocol-Version", version)
	}

	response, err := client.Do(request)
	if err != nil {
		return result, safeOriginProbeError(probeCtx, err)
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode

	body, err := io.ReadAll(io.LimitReader(response.Body, originProbeMaxBodyBytes+1))
	if err != nil {
		return result, errors.New("MCP Origin probe could not read the bounded response")
	}
	if len(body) > originProbeMaxBodyBytes {
		return result, fmt.Errorf("MCP Origin probe response exceeded %d bytes", originProbeMaxBodyBytes)
	}

	sessionID := strings.TrimSpace(response.Header.Get("Mcp-Session-Id"))
	if sessionID != "" {
		result.Outcome = OriginValidationAccepted
		result.Evidence = "session_allocated"
		cleanupTimeout := timeout
		if cleanupTimeout <= 0 || cleanupTimeout > 5*time.Second {
			cleanupTimeout = 5 * time.Second
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		result.CleanupStatus = cleanupOriginProbeSession(
			cleanupCtx, client, endpoint, protocolVersion, sessionID,
		)
		cleanupCancel()
		if result.CleanupStatus != "restored" {
			return result, errors.New("MCP Origin probe session cleanup was not confirmed")
		}
		return result, nil
	}
	if response.StatusCode == http.StatusForbidden {
		result.Outcome = OriginValidationRejected
		result.Evidence = "http_403"
		return result, nil
	}
	if containsMatchingJSONRPCResponse(body, requestID) {
		result.Outcome = OriginValidationAccepted
		result.Evidence = "matching_jsonrpc_response"
	}
	return result, nil
}

func cleanupOriginProbeSession(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	protocolVersion string,
	sessionID string,
) string {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return "unresolved"
	}
	request.Header.Set("Mcp-Session-Id", sessionID)
	if version := strings.TrimSpace(protocolVersion); version != "" {
		request.Header.Set("MCP-Protocol-Version", version)
	}
	response, err := client.Do(request)
	if err != nil {
		return "unresolved"
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, originProbeMaxBodyBytes))
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices ||
		response.StatusCode == http.StatusNotFound {
		return "restored"
	}
	return "unresolved"
}

func containsMatchingJSONRPCResponse(body []byte, requestID string) bool {
	if matchingJSONRPCResponse(body, requestID) {
		return true
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		if matchingJSONRPCResponse([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), requestID) {
			return true
		}
	}
	return false
}

func matchingJSONRPCResponse(body []byte, requestID string) bool {
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil ||
		response.JSONRPC != "2.0" || response.Method != "" ||
		(len(response.Result) == 0 && len(response.Error) == 0) {
		return false
	}
	var actualID string
	return json.Unmarshal(response.ID, &actualID) == nil && actualID == requestID
}

func safeOriginProbeError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, contact.ErrExcluded):
		return fmt.Errorf("MCP Origin probe target excluded: %w", contact.ErrExcluded)
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("MCP Origin probe canceled: %w", context.Canceled)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("MCP Origin probe deadline exceeded: %w", context.DeadlineExceeded)
	default:
		return errors.New("MCP Origin probe transport failed")
	}
}

// Package apiclient is the collector's HTTP client for talking to an
// agenthound-server. It is auth-less by design (single-user posture); the
// server is expected to be reached over an operator-controlled network
// (localhost, VPN, SSH tunnel).
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New constructs a Client that targets the given baseURL.
//
// The Client carries no credentials. Reach the server through your own
// network protection (localhost, VPN, SSH tunnel).
func New(baseURL string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{},
	}
}

func (c *Client) Health(ctx context.Context) error {
	resp, cancel, err := c.do(ctx, http.MethodGet, "/api/v1/health", nil, 5*time.Second)
	if err != nil {
		return err
	}
	defer cancel()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.handleError(resp)
	}
	return nil
}

func (c *Client) Ingest(ctx context.Context, data *ingest.IngestData) (*ingest.IngestResult, error) {
	resp, cancel, err := c.do(ctx, http.MethodPost, "/api/v1/ingest", data, 120*time.Second)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var result ingest.IngestResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse ingest response: %w", err)
	}
	return &result, nil
}

// Finding mirrors server/model.Finding for collector-side decoding without
// importing the server package (collectors must not depend on server code).
type Finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	EdgeKind    string   `json:"edge_kind"`
	SourceID    string   `json:"source_id"`
	SourceName  string   `json:"source_name"`
	SourceKind  string   `json:"source_kind"`
	TargetID    string   `json:"target_id"`
	TargetName  string   `json:"target_name"`
	TargetKind  string   `json:"target_kind"`
	Confidence  float64  `json:"confidence"`
	OWASPMap    []string `json:"owasp_map,omitempty"`
}

func (c *Client) GetFindings(ctx context.Context, severity string) ([]Finding, error) {
	path := "/api/v1/analysis/findings"
	if severity != "" {
		path += "?severity=" + severity
	}

	resp, cancel, err := c.do(ctx, http.MethodGet, path, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var findings []Finding
	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		return nil, fmt.Errorf("failed to parse findings response: %w", err)
	}
	return findings, nil
}

func (c *Client) GetPrebuilt(ctx context.Context, id string) ([]map[string]any, error) {
	resp, cancel, err := c.do(ctx, http.MethodGet, "/api/v1/analysis/prebuilt/"+id, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var rows []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("failed to parse prebuilt response: %w", err)
	}
	return rows, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any, timeout time.Duration) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			cancel()
			return nil, nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		cancel()
		if isConnectionRefused(err) {
			return nil, nil, fmt.Errorf("cannot reach server at %s: is it running?", c.baseURL)
		}
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	return resp, cancel, nil
}

type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *Client) handleError(resp *http.Response) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("rate limited by server, wait and retry")
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == http.StatusBadRequest {
		var errResp errorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return fmt.Errorf("bad request: %s", errResp.Error.Message)
		}
		return fmt.Errorf("bad request: %s", string(body))
	}

	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error (%d): check server logs", resp.StatusCode)
	}

	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
}

func isConnectionRefused(err error) bool {
	return strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "dial tcp") ||
		strings.Contains(err.Error(), "no such host")
}

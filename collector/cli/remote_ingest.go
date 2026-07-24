package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	remoteIngestTimeout       = 5 * time.Minute
	remoteIngestResponseLimit = 16 << 20
)

func postRemoteIngest(
	ctx context.Context,
	serverURL string,
	artifact []byte,
) (*ingest.IngestResult, error) {
	endpoint, err := resolveRemoteIngestEndpoint(serverURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(artifact),
	)
	if err != nil {
		return nil, fmt.Errorf("create ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: remoteIngestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ingest request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, remoteIngestResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read ingest response: %w", err)
	}
	if len(body) > remoteIngestResponseLimit {
		return nil, fmt.Errorf("ingest response exceeds %d bytes", remoteIngestResponseLimit)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, remoteIngestHTTPError(resp.StatusCode, body)
	}

	var result ingest.IngestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode ingest response: %w", err)
	}
	return &result, nil
}

func resolveRemoteIngestEndpoint(serverURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return "", fmt.Errorf("invalid --ingest URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid --ingest URL: scheme must be http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid --ingest URL: provide a server base URL without credentials, query, or fragment")
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	switch path {
	case "":
		parsed.Path = "/api/v1/ingest"
		parsed.RawPath = ""
	case "/api/v1/ingest":
		parsed.Path = path
		parsed.RawPath = ""
	default:
		return "", fmt.Errorf("invalid --ingest URL: path must be empty or /api/v1/ingest")
	}
	return parsed.String(), nil
}

func remoteIngestHTTPError(status int, body []byte) error {
	var response struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &response); err == nil && response.Error.Message != "" {
		if response.Error.Code != "" {
			return fmt.Errorf("ingest failed with HTTP %d (%s): %s", status, response.Error.Code, response.Error.Message)
		}
		return fmt.Errorf("ingest failed with HTTP %d: %s", status, response.Error.Message)
	}
	return fmt.Errorf("ingest failed with HTTP %d", status)
}

func writeRemoteIngestResult(
	w io.Writer,
	result *ingest.IngestResult,
	artifactPath string,
	fullJSON bool,
) error {
	if result == nil {
		return fmt.Errorf("ingest returned no result")
	}
	if fullJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("write ingest result: %w", err)
		}
		return nil
	}

	heading := "Ingest complete"
	if !remoteIngestComplete(result) {
		heading = "Ingest incomplete"
	}
	if _, err := fmt.Fprintf(
		w,
		"%s:\n\n  Scan ID:   %s\n  Artifact:  %s\n  Nodes:     %d\n  Edges:     %d\n  Findings:  %d\n  Duration:  %s\n",
		heading,
		result.ScanID,
		artifactPath,
		result.Submitted.Nodes,
		result.Submitted.Edges,
		result.Findings,
		result.Duration.Round(time.Millisecond),
	); err != nil {
		return fmt.Errorf("write ingest result: %w", err)
	}
	return nil
}

func validateRemoteIngestResult(result *ingest.IngestResult) error {
	if result == nil {
		return fmt.Errorf("ingest returned no result")
	}
	if remoteIngestComplete(result) {
		return nil
	}
	return fmt.Errorf(
		"ingest did not publish a complete projection: outcome=%s projection=%s",
		result.Outcome,
		result.ProjectionStatus,
	)
}

func remoteIngestComplete(result *ingest.IngestResult) bool {
	return result != nil &&
		result.Outcome == ingest.OutcomeComplete &&
		result.ProjectionStatus == "complete" &&
		result.PublishedRevision != nil
}

// Package mlflowloot implements the v0.4 MLflow Looter.
//
// MLflow Tracking Server (default port 5000) exposes experiment
// metadata, run history, and artifact download via a REST API that is
// anonymous by default. The Looter surfaces:
//
//	GET /api/2.0/mlflow/experiments/search — list all experiments
//	GET /api/2.0/mlflow/runs/search        — list runs per experiment
//
// Emits one :MLflowServer node (MERGE-safe with fingerprinter) plus
// metadata properties (experiment_count, total_runs). Full artifact
// download (model binaries) stays out-of-scope for v0.4 — the
// Extractor interface handles that downstream.
package mlflowloot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 5000
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 1000
)

type Looter struct{}

func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	host, port := splitHostPort(t.Address, DefaultPort)
	scheme := "http"
	if s, ok := t.Meta["scheme"]; ok && s != "" {
		scheme = s
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	mlflowID := ingest.ComputeNodeID("MLflowServer", baseURL)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res := &action.LootResult{IngestData: &ingest.IngestData{}}

	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    mlflowID,
		Kinds: []string{"MLflowServer", "AIService"},
		Properties: map[string]any{
			"objectid":          mlflowID,
			"endpoint":          baseURL,
			"name":              host,
			"discovered_via":    "mlflow_loot",
			"service_kind":      "mlflow",
			"auth_method":       "none",
			"is_anonymous_loot": "true",
		},
	})
	res.Summary.EndpointsProbed++

	experiments, err := fetchExperiments(ctx, client, baseURL)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("mlflow loot: experiments/search failed", "error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("experiments/search: %v", err))
		res.Summary.PartialFailures++
	} else {
		res.IngestData.Graph.Nodes[0].Properties["experiment_count"] = len(experiments)
	}

	var totalRuns int
	for _, exp := range experiments {
		runs, err := fetchRuns(ctx, client, baseURL, exp.ID)
		res.Summary.EndpointsProbed++
		if err != nil {
			slog.Debug("mlflow loot: runs/search failed for experiment", "experiment_id", exp.ID, "error", err)
			continue
		}
		totalRuns += len(runs)
	}
	res.IngestData.Graph.Nodes[0].Properties["total_runs"] = totalRuns
	res.Summary.CredentialsFound = len(experiments)

	slog.Info("mlflow loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"experiments", len(experiments),
		"total_runs", totalRuns,
		"partial_failures", res.Summary.PartialFailures)
	return res, nil
}

type experiment struct {
	ID   string `json:"experiment_id"`
	Name string `json:"name"`
}

func fetchExperiments(ctx context.Context, client *http.Client, baseURL string) ([]experiment, error) {
	body, err := getJSON(ctx, client, baseURL+"/api/2.0/mlflow/experiments/search")
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Experiments []experiment `json:"experiments"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode experiments: %w", err)
	}
	return parsed.Experiments, nil
}

type run struct {
	Info struct {
		RunID string `json:"run_id"`
	} `json:"info"`
}

func fetchRuns(ctx context.Context, client *http.Client, baseURL, experimentID string) ([]run, error) {
	u := baseURL + "/api/2.0/mlflow/runs/search"
	payload, _ := json.Marshal(map[string]any{
		"experiment_ids": []string{experimentID},
	})
	body, err := postJSON(ctx, client, u, payload)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Runs []run `json:"runs"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode runs: %w", err)
	}
	return parsed.Runs, nil
}

func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

func postJSON(ctx context.Context, client *http.Client, url string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

func splitHostPort(addr string, defaultPort int) (string, int) {
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			return splitHostPort(u.Host, defaultPort)
		}
	}
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		host := addr[:i]
		var p int
		_, _ = fmt.Sscanf(addr[i+1:], "%d", &p)
		if p > 0 {
			host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
			return host, p
		}
	}
	host := strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	return host, defaultPort
}

var _ action.Looter = (*Looter)(nil)

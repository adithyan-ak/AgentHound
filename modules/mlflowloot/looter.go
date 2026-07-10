// Package mlflowloot implements the v0.4 MLflow Looter.
//
// MLflow Tracking Server (default port 5000) exposes experiment
// metadata, run history, and Model Registry contents via a REST API
// that is anonymous by default on stock deployments. The Looter
// surfaces:
//
//	GET  /api/2.0/mlflow/experiments/search      — paginated experiments
//	POST /api/2.0/mlflow/runs/search             — paginated runs per experiment
//	GET  /api/2.0/mlflow/registered-models/search — Model Registry names
//	GET  /api/2.0/mlflow/model-versions/search   — Model Registry versions
//	GET  /api/2.0/mlflow/model-versions/get-download-uri — per-version storage URI
//
// The get-download-uri response is the plain storage_location (or the
// source field as a fallback) from the Model Registry — an s3://,
// gs://, azure://, dbfs:/, file:///, or hdfs:// URI. It is NOT a
// presigned URL and NOT credential material (mlflow/store/model_registry/
// sqlalchemy_store.py::get_model_version_download_uri returns
// sql_model_version.storage_location or sql_model_version.source
// verbatim). Each URI is emitted as an :MCPResource joined to the
// MLflowServer via PROVIDES_RESOURCE, with sensitivity auto-classified
// by scheme + path pattern per docs/reference/graph-model.md.
//
// Every probe sends max_results and follows next_page_token; modern
// MLflow (2.22.x+) rejects GET /experiments/search without max_results
// with INVALID_PARAMETER_VALUE (HTTP 400), so this is not optional.
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
	"path"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 5000
	DefaultProbeTimeout = 30 * time.Second
	// DefaultMaxItems bounds each per-page-loop enumeration
	// (experiments, runs-per-experiment, registered models, model
	// versions). MLflow's proto default for runs is 1000; experiments
	// has no explicit default but modern servers require max_results.
	DefaultMaxItems = 1000

	// pageSize is what we request per page. MLflow's SearchRuns proto
	// enforces its own 1000 upper bound, matching this constant.
	pageSize = 1000
)

type Looter struct{}

func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")
	mlflowID := ingest.ComputeNodeID("MLflowServer", baseURL)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}

	client := common.NoRedirectClient(timeout)

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

	// 1. /experiments/search (paginated).
	experiments, err := fetchExperiments(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("mlflow loot: experiments/search failed", "error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("experiments/search: %v", err))
		res.Summary.PartialFailures++
	} else {
		res.IngestData.Graph.Nodes[0].Properties["experiment_count"] = len(experiments)
	}

	// 2. /runs/search per experiment (paginated).
	var totalRuns int
	for _, exp := range experiments {
		runs, err := fetchRuns(ctx, client, baseURL, exp.ID, maxItems)
		res.Summary.EndpointsProbed++
		if err != nil {
			slog.Debug("mlflow loot: runs/search failed for experiment", "experiment_id", exp.ID, "error", err)
			continue
		}
		totalRuns += len(runs)
	}
	res.IngestData.Graph.Nodes[0].Properties["total_runs"] = totalRuns

	// 3. Model Registry: registered-models/search + model-versions/search
	//    + per-version get-download-uri. All GET, all paginated. Any
	//    probe returning non-2xx records a partial failure and the
	//    Registry branch stops; the MLflow inventory props still land.
	registered, regErr := fetchRegisteredModels(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if regErr != nil {
		slog.Warn("mlflow loot: registered-models/search failed", "error", regErr)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("registered-models/search: %v", regErr))
		res.Summary.PartialFailures++
	} else {
		res.IngestData.Graph.Nodes[0].Properties["registered_model_count"] = len(registered)
		names := make([]string, 0, len(registered))
		for _, m := range registered {
			names = append(names, m.Name)
		}
		res.IngestData.Graph.Nodes[0].Properties["registered_models"] = names
	}

	versions, verErr := fetchModelVersions(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if verErr != nil {
		slog.Warn("mlflow loot: model-versions/search failed", "error", verErr)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("model-versions/search: %v", verErr))
		res.Summary.PartialFailures++
	} else {
		res.IngestData.Graph.Nodes[0].Properties["model_version_count"] = len(versions)
	}

	// For each model version, fetch the download URI and emit an
	// :MCPResource + PROVIDES_RESOURCE edge. Individual failures are
	// per-version partials — one bad model shouldn't kill the walk.
	for _, v := range versions {
		uri, err := fetchDownloadURI(ctx, client, baseURL, v.Name, v.Version)
		res.Summary.EndpointsProbed++
		if err != nil {
			slog.Debug("mlflow loot: get-download-uri failed",
				"model", v.Name, "version", v.Version, "error", err)
			res.PartialErrors = append(res.PartialErrors,
				fmt.Sprintf("model-versions/get-download-uri %s:%s: %v", v.Name, v.Version, err))
			res.Summary.PartialFailures++
			continue
		}
		if uri == "" {
			continue
		}
		resourceID := ingest.ComputeNodeID("MCPResource", mlflowID, uri)
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID:    resourceID,
			Kinds: []string{"MCPResource"},
			Properties: map[string]any{
				"objectid":    resourceID,
				"uri":         uri,
				"name":        v.Name + ":" + v.Version,
				"mime_type":   "application/x-mlflow-model",
				"uri_scheme":  parseURIScheme(uri),
				"sensitivity": classifyArtifactSensitivity(uri),
			},
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, ingest.Edge{
			Source:     mlflowID,
			Target:     resourceID,
			Kind:       "PROVIDES_RESOURCE",
			SourceKind: "MLflowServer",
			TargetKind: "MCPResource",
			Properties: map[string]any{
				"confidence":  1.0,
				"risk_weight": 0.2,
				"evidence": map[string]any{
					"endpoint":      baseURL,
					"source":        "model_registry",
					"engagement_id": opts.EngagementID,
					"model_name":    v.Name,
					"model_version": v.Version,
				},
			},
		})
	}

	slog.Info("mlflow loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"experiments", len(experiments),
		"total_runs", totalRuns,
		"registered_models", len(registered),
		"model_versions", len(versions),
		"partial_failures", res.Summary.PartialFailures)
	return res, nil
}

type experiment struct {
	ID   string `json:"experiment_id"`
	Name string `json:"name"`
}

// clampPageSize returns the per-request page size given the caller's
// remaining budget and MLflow's per-endpoint upper bound.
func clampPageSize(remaining int) int {
	if remaining <= 0 || remaining > pageSize {
		return pageSize
	}
	return remaining
}

func fetchExperiments(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]experiment, error) {
	var out []experiment
	pageToken := ""
	for {
		remaining := maxItems - len(out)
		if remaining <= 0 {
			break
		}
		u := fmt.Sprintf("%s/api/2.0/mlflow/experiments/search?max_results=%d",
			baseURL, clampPageSize(remaining))
		if pageToken != "" {
			u += "&page_token=" + url.QueryEscape(pageToken)
		}
		body, err := common.GetJSON(ctx, client, u, "", 4<<20)
		if err != nil {
			if len(out) == 0 {
				return nil, err
			}
			return out, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			Experiments   []experiment `json:"experiments"`
			NextPageToken string       `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode experiments: %w", err)
		}
		out = append(out, parsed.Experiments...)
		if parsed.NextPageToken == "" || len(parsed.Experiments) == 0 {
			break
		}
		pageToken = parsed.NextPageToken
	}
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out, nil
}

type run struct {
	Info struct {
		RunID string `json:"run_id"`
	} `json:"info"`
}

func fetchRuns(ctx context.Context, client *http.Client, baseURL, experimentID string, maxItems int) ([]run, error) {
	var out []run
	pageToken := ""
	for {
		remaining := maxItems - len(out)
		if remaining <= 0 {
			break
		}
		payload := map[string]any{
			"experiment_ids": []string{experimentID},
			"max_results":    clampPageSize(remaining),
		}
		if pageToken != "" {
			payload["page_token"] = pageToken
		}
		bs, _ := json.Marshal(payload)
		body, err := postJSON(ctx, client, baseURL+"/api/2.0/mlflow/runs/search", bs)
		if err != nil {
			if len(out) == 0 {
				return nil, err
			}
			return out, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			Runs          []run  `json:"runs"`
			NextPageToken string `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode runs: %w", err)
		}
		out = append(out, parsed.Runs...)
		if parsed.NextPageToken == "" || len(parsed.Runs) == 0 {
			break
		}
		pageToken = parsed.NextPageToken
	}
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out, nil
}

type registeredModel struct {
	Name string `json:"name"`
}

// fetchRegisteredModels enumerates the Model Registry via GET
// /api/2.0/mlflow/registered-models/search. Anonymous-readable on stock
// MLflow, paginated via next_page_token.
func fetchRegisteredModels(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]registeredModel, error) {
	var out []registeredModel
	pageToken := ""
	for {
		remaining := maxItems - len(out)
		if remaining <= 0 {
			break
		}
		u := fmt.Sprintf("%s/api/2.0/mlflow/registered-models/search?max_results=%d",
			baseURL, clampPageSize(remaining))
		if pageToken != "" {
			u += "&page_token=" + url.QueryEscape(pageToken)
		}
		body, err := common.GetJSON(ctx, client, u, "", 4<<20)
		if err != nil {
			if len(out) == 0 {
				return nil, err
			}
			return out, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			RegisteredModels []registeredModel `json:"registered_models"`
			NextPageToken    string            `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode registered_models: %w", err)
		}
		out = append(out, parsed.RegisteredModels...)
		if parsed.NextPageToken == "" || len(parsed.RegisteredModels) == 0 {
			break
		}
		pageToken = parsed.NextPageToken
	}
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out, nil
}

type modelVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// fetchModelVersions enumerates all model versions across all
// registered models via GET /api/2.0/mlflow/model-versions/search.
// MLflow returns (name, version) pairs which the caller uses to build
// per-version get-download-uri probes.
func fetchModelVersions(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]modelVersion, error) {
	var out []modelVersion
	pageToken := ""
	for {
		remaining := maxItems - len(out)
		if remaining <= 0 {
			break
		}
		u := fmt.Sprintf("%s/api/2.0/mlflow/model-versions/search?max_results=%d",
			baseURL, clampPageSize(remaining))
		if pageToken != "" {
			u += "&page_token=" + url.QueryEscape(pageToken)
		}
		body, err := common.GetJSON(ctx, client, u, "", 4<<20)
		if err != nil {
			if len(out) == 0 {
				return nil, err
			}
			return out, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			ModelVersions []modelVersion `json:"model_versions"`
			NextPageToken string         `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode model_versions: %w", err)
		}
		out = append(out, parsed.ModelVersions...)
		if parsed.NextPageToken == "" || len(parsed.ModelVersions) == 0 {
			break
		}
		pageToken = parsed.NextPageToken
	}
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out, nil
}

// fetchDownloadURI issues GET /api/2.0/mlflow/model-versions/get-download-uri
// and returns the artifact_uri string. Per mlflow/store/model_registry/
// sqlalchemy_store.py::get_model_version_download_uri (line 1291-1306),
// the returned URI is sql_model_version.storage_location or
// sql_model_version.source verbatim — a plain storage URI, NOT a
// presigned/pre-signed credential.
func fetchDownloadURI(ctx context.Context, client *http.Client, baseURL, name, version string) (string, error) {
	u := fmt.Sprintf("%s/api/2.0/mlflow/model-versions/get-download-uri?name=%s&version=%s",
		baseURL, url.QueryEscape(name), url.QueryEscape(version))
	body, err := common.GetJSON(ctx, client, u, "", 1<<20)
	if err != nil {
		return "", err
	}
	var parsed struct {
		ArtifactURI string `json:"artifact_uri"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode get-download-uri: %w", err)
	}
	return strings.TrimSpace(parsed.ArtifactURI), nil
}

// parseURIScheme extracts the scheme (before "://") from a storage URI.
// Returns empty when the URI has no scheme.
func parseURIScheme(uri string) string {
	if i := strings.Index(uri, "://"); i > 0 {
		return strings.ToLower(uri[:i])
	}
	// Some MLflow artifact URIs are dbfs:/path (single colon).
	if i := strings.Index(uri, ":"); i > 0 {
		return strings.ToLower(uri[:i])
	}
	return ""
}

// classifyArtifactSensitivity assigns a graph-model sensitivity level
// to an MLflow artifact URI, mirroring the auto-classification table in
// docs/reference/graph-model.md:248-256:
//
//   - critical: file:///etc/* paths; secret-bearing extensions
//     (.env / .key / .pem); prod cloud buckets.
//   - high:     other cloud storage (s3/gs/azure/abfs/dbfs/hdfs).
//   - medium:   other file:// URIs.
//   - fallback: high (Model Registry artifacts are typically protected).
func classifyArtifactSensitivity(uri string) string {
	lower := strings.ToLower(uri)
	scheme := parseURIScheme(lower)

	// Extension-based critical classification (env/key/pem) applies
	// regardless of scheme.
	ext := strings.ToLower(path.Ext(strings.TrimRight(lower, "/")))
	if ext == ".env" || ext == ".key" || ext == ".pem" {
		return "critical"
	}
	cloudSchemes := map[string]bool{
		"s3": true, "gs": true, "azure": true, "abfs": true, "abfss": true,
		"wasb": true, "wasbs": true, "dbfs": true, "hdfs": true,
	}
	// Cloud bucket + prod indicator → critical.
	if cloudSchemes[scheme] && strings.Contains(lower, "prod") {
		return "critical"
	}
	// file:///etc/ → critical.
	if scheme == "file" && strings.Contains(lower, "file:///etc/") {
		return "critical"
	}
	if cloudSchemes[scheme] {
		return "high"
	}
	if scheme == "file" {
		return "medium"
	}
	return "high"
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

var _ action.Looter = (*Looter)(nil)

// Package mlflowcollect implements the MLflow Collector.
//
// MLflow Tracking Server (default port 5000) exposes experiment
// metadata, run history, and Model Registry contents via a REST API
// that is anonymous by default on stock deployments. The Collector
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
// verbatim). Each registered model version is emitted as a ModelArtifact.
// Safely canonicalizable physical roots are represented once as ArtifactStore
// and joined with STORED_IN; unresolved MLflow locators remain metadata only.
//
// Every probe sends max_results and follows next_page_token; modern
// MLflow (2.22.x+) rejects GET /experiments/search without max_results
// with INVALID_PARAMETER_VALUE (HTTP 400), so this is not optional.
package mlflowcollect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
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

type Collector struct{}

func (l *Collector) Collect(ctx context.Context, t action.Target, opts action.CollectOptions) (*action.CollectResult, error) {
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

	res := &action.CollectResult{
		IngestData: &ingest.IngestData{},
		Inventory: &action.InventoryResult{
			Name: "model_registry", State: ingest.OutcomeFailed,
		},
	}

	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    mlflowID,
		Kinds: []string{"MLflowServer", "AIService"},
		Properties: map[string]any{
			"objectid":            mlflowID,
			"endpoint":            baseURL,
			"name":                host,
			"collection_observed": true,
			"service_kind":        "mlflow",
		},
	})
	res.Summary.EndpointsProbed++

	// 1. /experiments/search (paginated).
	experiments, err := fetchExperiments(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("mlflow collection: experiments/search failed", "error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("experiments/search: %v", err))
		res.Summary.PartialFailures++
	} else {
		props := res.IngestData.Graph.Nodes[0].Properties
		props["experiment_count"] = len(experiments)
		markAnonymousInventorySuccess(props)
	}
	if ctx.Err() != nil {
		return res, nil
	}

	// 2. /runs/search per experiment (paginated).
	var totalRuns int
	for _, exp := range experiments {
		if ctx.Err() != nil {
			break
		}
		runs, err := fetchRuns(ctx, client, baseURL, exp.ID, maxItems)
		res.Summary.EndpointsProbed++
		if err != nil {
			slog.Debug("mlflow collection: runs/search failed for experiment", "experiment_id", exp.ID, "error", err)
			continue
		}
		totalRuns += len(runs)
	}
	res.IngestData.Graph.Nodes[0].Properties["total_runs"] = totalRuns
	if ctx.Err() != nil {
		return res, nil
	}

	// 3. Model Registry: registered-models/search + model-versions/search
	//    + per-version get-download-uri. All GET, all paginated. Any
	//    probe returning non-2xx records a partial failure and the
	//    Registry branch stops; the MLflow inventory props still land.
	registered, registeredTruncated, regErr := fetchRegisteredModels(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if regErr != nil {
		slog.Warn("mlflow collection: registered-models/search failed", "error", regErr)
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
	if ctx.Err() != nil {
		return res, nil
	}

	versions, versionsTruncated, verErr := fetchModelVersions(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if verErr != nil {
		slog.Warn("mlflow collection: model-versions/search failed", "error", verErr)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("model-versions/search: %v", verErr))
		res.Summary.PartialFailures++
	} else {
		res.IngestData.Graph.Nodes[0].Properties["model_version_count"] = len(versions)
	}
	res.Inventory.Items = len(versions)
	res.Inventory.State = modelRegistryState(
		regErr, verErr, registeredTruncated, versionsTruncated,
	)
	for _, inventoryErr := range []error{regErr, verErr} {
		if inventoryErr != nil {
			res.Inventory.Error = appendInventoryError(res.Inventory.Error, inventoryErr.Error())
		}
	}
	if registeredTruncated {
		message := fmt.Sprintf("registered models truncated at max_items=%d", maxItems)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		res.Inventory.Error = appendInventoryError(res.Inventory.Error, message)
	}
	if versionsTruncated {
		message := fmt.Sprintf("model versions truncated at max_items=%d", maxItems)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		res.Inventory.Error = appendInventoryError(res.Inventory.Error, message)
	}
	if ctx.Err() != nil {
		res.Inventory.State = ingest.OutcomePartial
		res.Inventory.Error = appendInventoryError(res.Inventory.Error, ctx.Err().Error())
		return res, nil
	}

	// Each enumerated immutable model version becomes a ModelArtifact. The
	// download URI enriches that artifact but never defines its identity.
	// Individual lookup failures keep this inventory non-authoritative.
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].Name == versions[j].Name {
			return versions[i].Version < versions[j].Version
		}
		return versions[i].Name < versions[j].Name
	})
	lastSeen := time.Now().UTC().Format(time.RFC3339)
	storeNodes := make(map[string]bool)
	for _, v := range versions {
		if ctx.Err() != nil {
			res.Inventory.State = ingest.OutcomePartial
			res.Inventory.Error = appendInventoryError(res.Inventory.Error, ctx.Err().Error())
			break
		}
		artifactID := ingest.ComputeNodeID("ModelArtifact", mlflowID, v.Name, v.Version)
		artifactProps := map[string]any{
			"objectid": artifactID, "name": v.Name, "version": v.Version,
			"display_name": v.Name + ":" + v.Version, "sensitivity": "high",
		}
		uri, downloadErr := fetchDownloadURI(ctx, client, baseURL, v.Name, v.Version)
		res.Summary.EndpointsProbed++
		if downloadErr != nil {
			slog.Debug("mlflow collection: get-download-uri failed",
				"model", v.Name, "version", v.Version, "error", downloadErr)
			message := fmt.Sprintf(
				"model-versions/get-download-uri %s:%s: %v",
				v.Name, v.Version, downloadErr,
			)
			res.PartialErrors = append(res.PartialErrors,
				message)
			res.Summary.PartialFailures++
			if res.Inventory.State == ingest.OutcomeComplete {
				res.Inventory.State = ingest.OutcomePartial
			}
			res.Inventory.Error = appendInventoryError(res.Inventory.Error, message)
		} else if sanitizedURI := sanitizeArtifactURI(uri); sanitizedURI != "" {
			artifactProps["storage_uri"] = sanitizedURI
			artifactProps["storage_scheme"] = parseURIScheme(sanitizedURI)
			artifactProps["sensitivity"] = classifyArtifactSensitivity(sanitizedURI)
		}
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID: artifactID, Kinds: []string{"ModelArtifact"}, Properties: artifactProps,
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, ingest.Edge{
			Source: mlflowID, Target: artifactID, Kind: "PROVIDES_RESOURCE",
			SourceKind: "MLflowServer", TargetKind: "ModelArtifact",
			Properties: map[string]any{
				"confidence": 1.0, "risk_weight": 0.2,
				"evidence_state": string(ingest.EvidenceVerified), "last_seen": lastSeen,
				"evidence": map[string]any{
					"endpoint": baseURL, "source": "model-versions/search",
					"model_name": v.Name, "model_version": v.Version,
				},
			},
		})

		store, ok := canonicalArtifactStore(uri, mlflowID)
		if !ok {
			continue
		}
		if !storeNodes[store.ID] {
			storeNodes[store.ID] = true
			res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
				ID: store.ID, Kinds: []string{"ArtifactStore"},
				Properties: map[string]any{
					"objectid": store.ID, "name": store.RootURI,
					"provider": store.Provider, "root_uri": store.RootURI,
					"scope": store.Scope, "sensitivity": "high",
				},
			})
		}
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, ingest.Edge{
			Source: artifactID, Target: store.ID, Kind: "STORED_IN",
			SourceKind: "ModelArtifact", TargetKind: "ArtifactStore",
			Properties: map[string]any{
				"confidence": 1.0, "risk_weight": 0.2,
				"evidence_state": string(ingest.EvidenceObserved), "last_seen": lastSeen,
				"evidence": map[string]any{
					"source": "get-download-uri", "provider": store.Provider,
					"root_uri": store.RootURI,
				},
			},
		})
	}

	slog.Info("mlflow collection complete",
		"endpoint", baseURL,
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
			Experiments   json.RawMessage `json:"experiments"`
			NextPageToken string          `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode experiments: %w", err)
		}
		experimentsJSON := bytes.TrimSpace(parsed.Experiments)
		if len(experimentsJSON) == 0 || experimentsJSON[0] != '[' {
			return nil, errors.New("decode experiments: expected an experiments array")
		}
		var pageExperiments []experiment
		if err := json.Unmarshal(experimentsJSON, &pageExperiments); err != nil {
			return nil, fmt.Errorf("decode experiments array: %w", err)
		}
		out = append(out, pageExperiments...)
		if parsed.NextPageToken == "" || len(pageExperiments) == 0 {
			break
		}
		pageToken = parsed.NextPageToken
	}
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out, nil
}

func markAnonymousInventorySuccess(props map[string]any) {
	props["auth_method"] = string(common.AuthNone)
	props["auth_assurance"] = string(common.AuthAssuranceUnauthenticated)
	props["auth_evidence"] = common.AuthEvidenceAnonymousProbeSucceeded
	props["probe_status"] = string(common.VerificationVerified)
	props["last_verified_at"] = time.Now().UTC().Format(time.RFC3339)
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
func fetchRegisteredModels(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]registeredModel, bool, error) {
	var out []registeredModel
	pageToken := ""
	truncated := false
	for {
		remaining := maxItems - len(out)
		if remaining <= 0 {
			truncated = pageToken != ""
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
				return nil, false, err
			}
			return out, false, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			RegisteredModels []registeredModel `json:"registered_models"`
			NextPageToken    string            `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, false, fmt.Errorf("decode registered_models: %w", err)
		}
		out = append(out, parsed.RegisteredModels...)
		if len(out) > maxItems {
			out = out[:maxItems]
			truncated = true
			break
		}
		if parsed.NextPageToken == "" || len(parsed.RegisteredModels) == 0 {
			break
		}
		pageToken = parsed.NextPageToken
	}
	return out, truncated, nil
}

type modelVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// fetchModelVersions enumerates all model versions across all
// registered models via GET /api/2.0/mlflow/model-versions/search.
// MLflow returns (name, version) pairs which the caller uses to build
// per-version get-download-uri probes.
func fetchModelVersions(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]modelVersion, bool, error) {
	var out []modelVersion
	pageToken := ""
	truncated := false
	for {
		remaining := maxItems - len(out)
		if remaining <= 0 {
			truncated = pageToken != ""
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
				return nil, false, err
			}
			return out, false, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			ModelVersions []modelVersion `json:"model_versions"`
			NextPageToken string         `json:"next_page_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, false, fmt.Errorf("decode model_versions: %w", err)
		}
		out = append(out, parsed.ModelVersions...)
		if len(out) > maxItems {
			out = out[:maxItems]
			truncated = true
			break
		}
		if parsed.NextPageToken == "" || len(parsed.ModelVersions) == 0 {
			break
		}
		pageToken = parsed.NextPageToken
	}
	return out, truncated, nil
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

func modelRegistryState(
	registeredErr error,
	versionsErr error,
	registeredTruncated bool,
	versionsTruncated bool,
) ingest.OutcomeState {
	if registeredErr != nil && versionsErr != nil {
		return ingest.OutcomeFailed
	}
	if registeredErr != nil || versionsErr != nil {
		return ingest.OutcomePartial
	}
	if registeredTruncated || versionsTruncated {
		return ingest.OutcomeTruncated
	}
	return ingest.OutcomeComplete
}

func appendInventoryError(current, next string) string {
	if current == "" {
		return next
	}
	if next == "" || strings.Contains(current, next) {
		return current
	}
	return current + "; " + next
}

type artifactStoreRef struct {
	ID       string
	Provider string
	RootURI  string
	Scope    string
}

// sanitizeArtifactURI removes credential-bearing and request-specific URL
// components before a registry locator is retained as graph metadata.
func sanitizeArtifactURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" {
		return ""
	}
	if parsed.Scheme == "" {
		if !strings.HasPrefix(parsed.Path, "/") {
			return ""
		}
		return path.Clean(parsed.Path)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	if parsed.Host != "" {
		host := strings.ToLower(parsed.Hostname())
		if host == "" {
			return ""
		}
		if port := parsed.Port(); port != "" {
			parsed.Host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			parsed.Host = "[" + host + "]"
		} else {
			parsed.Host = host
		}
	}
	if parsed.Path != "" {
		parsed.Path = path.Clean(parsed.Path)
		if parsed.Path == "." {
			parsed.Path = ""
		}
		parsed.RawPath = ""
	}
	return parsed.String()
}

// canonicalArtifactStore returns a logical physical storage root. MLflow
// indirection schemes (models, runs, mlflow-artifacts) intentionally return
// no store because they do not identify a physical root.
func canonicalArtifactStore(raw, mlflowID string) (artifactStoreRef, bool) {
	sanitized := sanitizeArtifactURI(raw)
	if sanitized == "" {
		return artifactStoreRef{}, false
	}
	parsed, err := url.Parse(sanitized)
	if err != nil {
		return artifactStoreRef{}, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	remoteProviders := map[string]bool{
		"s3": true, "gs": true, "azure": true, "abfs": true, "abfss": true,
		"wasb": true, "wasbs": true, "hdfs": true,
	}
	if remoteProviders[scheme] {
		if parsed.Hostname() == "" {
			return artifactStoreRef{}, false
		}
		root := (&url.URL{Scheme: scheme, Host: parsed.Host}).String()
		return artifactStoreRef{
			ID: ingest.ComputeNodeID("ArtifactStore", root), Provider: scheme,
			RootURI: root, Scope: "remote",
		}, true
	}

	var root string
	switch {
	case scheme == "file":
		root = (&url.URL{Scheme: "file", Host: parsed.Host, Path: "/"}).String()
	case scheme == "dbfs":
		root = "dbfs:/"
	case scheme == "" && strings.HasPrefix(sanitized, "/"):
		scheme = "file"
		root = "file:///"
	default:
		return artifactStoreRef{}, false
	}
	return artifactStoreRef{
		ID: ingest.ComputeNodeID("ArtifactStore", mlflowID, root), Provider: scheme,
		RootURI: root, Scope: "service",
	}, true
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

var _ action.ServiceCollector = (*Collector)(nil)

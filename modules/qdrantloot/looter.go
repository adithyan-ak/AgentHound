// Package qdrantloot implements the v0.4 Qdrant Looter.
//
// Qdrant is a vector database commonly fronted by LLM/RAG systems
// (default port 6333, REST API). By default Qdrant has NO auth, so the
// collection inventory and per-collection statistics are readable
// anonymously. The Looter surfaces:
//
//	GET /collections          — list collection names
//	GET /collections/{name}   — per-collection details (points_count, etc.)
//
// Both probes are pure GETs — Qdrant exposes the inventory without a
// search body, so this Looter has NO non-GET call sites (the strictest
// form of the read-only Looter contract).
//
// Emits inventory as PROPERTIES on the existing :QdrantInstance node
// (same objectid as qdrantfp via ComputeNodeID("QdrantInstance",
// endpoint), so the writer's MERGE-by-objectid fold enriches the
// fingerprinter's node rather than duplicating it). No new node/edge
// kinds. We deliberately model this as properties-on-instance over a
// dedicated KnowledgeBase node — YAGNI until a retrieval-edge consumer
// exists (#10 deferred).
package qdrantloot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 6333
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 1000
)

// Looter is the registered module.
type Looter struct{}

// Loot probes a Qdrant REST API anonymously, listing collections and
// their per-collection point counts, then folds an inventory summary
// onto the existing QdrantInstance node. Metadata-only: emits NO
// Credential nodes (Qdrant exposes data, not secrets, on the anonymous
// surface), so CredentialsFound stays 0.
func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")
	qdrantID := ingest.ComputeNodeID("QdrantInstance", baseURL)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res := &action.LootResult{IngestData: &ingest.IngestData{}}

	// Always emit the QdrantInstance node so the inventory properties have
	// a home. The fingerprinter may have produced this node on a prior
	// scan; MERGE-by-objectid folds these properties onto it.
	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    qdrantID,
		Kinds: []string{"QdrantInstance", "AIService"},
		Properties: map[string]any{
			"objectid":          qdrantID,
			"endpoint":          baseURL,
			"name":              host,
			"discovered_via":    "qdrant_loot",
			"service_kind":      "qdrant",
			"auth_method":       "none",
			"is_anonymous_loot": "true",
		},
	})
	res.Summary.EndpointsProbed++

	names, err := fetchCollections(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("qdrant loot: /collections failed",
			"endpoint", baseURL,
			"engagement_id", opts.EngagementID,
			"error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("collections: %v", err))
		res.Summary.PartialFailures++
		return res, nil
	}

	sort.Strings(names)

	var totalPoints int64
	for _, name := range names {
		points, detErr := fetchCollectionPoints(ctx, client, baseURL, name)
		res.Summary.EndpointsProbed++
		if detErr != nil {
			slog.Debug("qdrant loot: collection detail failed",
				"collection", name,
				"engagement_id", opts.EngagementID,
				"error", detErr)
			res.PartialErrors = append(res.PartialErrors,
				fmt.Sprintf("collections/%s: %v", name, detErr))
			res.Summary.PartialFailures++
			continue
		}
		totalPoints += points
	}

	props := res.IngestData.Graph.Nodes[0].Properties
	props["collection_count"] = len(names)
	props["collections"] = names
	props["total_points"] = totalPoints
	props["anonymous_listing"] = true

	slog.Info("qdrant loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"collections", len(names),
		"total_points", totalPoints,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// fetchCollections lists collection names. Qdrant's /collections returns
// {"result":{"collections":[{"name":...}]},"status":"ok",...}. Parsing
// is defensive — a missing or empty result yields an empty slice, not an
// error (an anonymous Qdrant with zero collections is still a finding).
func fetchCollections(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]string, error) {
	body, err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+"/collections")
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Result struct {
			Collections []struct {
				Name string `json:"name"`
			} `json:"collections"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode /collections: %w", err)
	}
	out := make([]string, 0, len(parsed.Result.Collections))
	for _, c := range parsed.Result.Collections {
		if c.Name == "" {
			continue
		}
		out = append(out, c.Name)
		if len(out) >= maxItems {
			break
		}
	}
	return out, nil
}

// fetchCollectionPoints reads /collections/{name} and returns the
// points_count. Qdrant returns
// {"result":{"points_count":N,"config":{...},"payload_schema":{...}},...}.
// A missing points_count is treated as zero rather than an error so a
// collection with an unexpected shape still contributes to the inventory
// count without inflating total_points with fabricated data.
func fetchCollectionPoints(ctx context.Context, client *http.Client, baseURL, name string) (int64, error) {
	u := strings.TrimRight(baseURL, "/") + "/collections/" + url.PathEscape(name)
	body, err := getJSON(ctx, client, u)
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Result struct {
			PointsCount int64 `json:"points_count"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, fmt.Errorf("decode /collections/%s: %w", name, err)
	}
	return parsed.Result.PointsCount, nil
}

// getJSON does the GET-and-read dance. 4 MiB cap matches the metadata
// scale of /collections responses — collection lists are small.
func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

var _ action.Looter = (*Looter)(nil)

// Package qdrantloot implements the v0.4 Qdrant Looter.
//
// Qdrant is a vector database commonly fronted by LLM/RAG systems
// (default port 6333, REST API). By default Qdrant has NO auth, so the
// collection inventory and per-collection statistics are readable
// anonymously. The Looter surfaces:
//
//	GET  /collections                            — list collection names
//	GET  /collections/{name}                     — per-collection details (points_count, etc.)
//	POST /collections/{name}/points/scroll       — paginated payload sampling (opt-in)
//
// The GET-only default has ONE POST exception: /points/scroll, which
// Qdrant's OpenAPI exposes only via POST. It is idempotent and
// read-only-in-effect (returns points + payload, no state change),
// documented at openapi.json ScrollRequest:10273 / ScrollResult:10411.
// The Looter runs it only when --include-points is supplied.
//
// Inventory emissions land as PROPERTIES on the existing
// :QdrantInstance node (same objectid as qdrantfp via
// ComputeNodeID("QdrantInstance", endpoint), so the writer's
// MERGE-by-objectid fold enriches the fingerprinter's node rather than
// duplicating it). Scrolled point payloads (when --include-points is
// set) land as :MCPResource nodes joined to QdrantInstance via
// PROVIDES_RESOURCE edges.
package qdrantloot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 6333
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 1000

	// DefaultCollectionConcurrency bounds the per-collection detail
	// fetches. Qdrant's /collections returns only names, so points_count
	// requires one GET per collection (an N+1 stall when done serially);
	// these run in a small worker pool instead. 16 is gentle on a single
	// host (networkscan uses 50 across many hosts).
	DefaultCollectionConcurrency = 16

	// DefaultPointsPerCollection caps the number of points sampled via
	// /points/scroll per collection when --include-points is set.
	DefaultPointsPerCollection = 100

	// DefaultMaxTotalResources caps the global number of :MCPResource
	// nodes the Looter will emit across all collections. Guards against
	// runaway scrolling on large Qdrant deployments.
	DefaultMaxTotalResources = 5000

	// scrollPageLimit is the per-request limit sent to /points/scroll.
	// Qdrant returns points + next_page_offset; we iterate until
	// next_page_offset is null OR per-collection cap OR global cap.
	scrollPageLimit = 256
)

// Looter is the registered module.
type Looter struct{}

// RegisterFlags satisfies module.FlagsModule. Flag values flow through
// LootOptions.Extras.
func (l *Looter) RegisterFlags(fs *pflag.FlagSet) {
	fs.Bool("include-points", false,
		"Sample per-collection payloads via POST /collections/{name}/points/scroll (opt-in; can be large).")
	fs.Int("points-per-collection", DefaultPointsPerCollection,
		"Cap on payloads sampled per collection when --include-points is set.")
	fs.Int("max-total-resources", DefaultMaxTotalResources,
		"Global cap on :MCPResource nodes emitted across all collections (prevents runaway on large deployments).")
}

// Loot probes a Qdrant REST API anonymously, listing collections and
// their per-collection point counts, then folds an inventory summary
// onto the existing QdrantInstance node. When --include-points is set,
// additionally samples each collection's payloads via POST
// /points/scroll and emits :MCPResource nodes.
//
// opts.Extras keys consumed by this Looter:
//
//	"include-points"         bool  — gate POST /points/scroll
//	"points-per-collection"  int   — per-collection sampling cap
//	"max-total-resources"    int   — global cap across all collections
func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	_, host, port := action.EndpointParts(t, DefaultPort, "http")
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

	includePoints, _ := opts.Extras["include-points"].(bool)
	perCollectionCap, _ := opts.Extras["points-per-collection"].(int)
	if perCollectionCap <= 0 {
		perCollectionCap = DefaultPointsPerCollection
	}
	globalCap, _ := opts.Extras["max-total-resources"].(int)
	if globalCap <= 0 {
		globalCap = DefaultMaxTotalResources
	}

	client := common.NoRedirectClient(timeout)

	res := &action.LootResult{IngestData: &ingest.IngestData{}}

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

	// Per-collection point-count fetches — bounded worker pool.
	conc := DefaultCollectionConcurrency
	if conc > len(names) {
		conc = len(names)
	}

	points := make([]*int64, len(names))
	detErrs := make([]string, len(names))
	idxs := make(chan int)

	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idxs {
				p, detErr := fetchCollectionPoints(ctx, client, baseURL, names[i])
				if detErr != nil {
					detErrs[i] = fmt.Sprintf("collections/%s: %v", names[i], detErr)
					continue
				}
				points[i] = p
			}
		}()
	}
	for i := range names {
		idxs <- i
	}
	close(idxs)
	wg.Wait()

	var totalPoints int64
	var pointsCountUnknown int
	for i := range names {
		res.Summary.EndpointsProbed++
		if detErrs[i] != "" {
			slog.Debug("qdrant loot: collection detail failed",
				"collection", names[i],
				"engagement_id", opts.EngagementID,
				"error", detErrs[i])
			res.PartialErrors = append(res.PartialErrors, detErrs[i])
			res.Summary.PartialFailures++
			continue
		}
		if points[i] == nil {
			// Qdrant OpenAPI declares points_count as integer | null.
			// A missing/null value is "unknown" — do not conflate with 0.
			pointsCountUnknown++
			continue
		}
		totalPoints += *points[i]
	}

	props := res.IngestData.Graph.Nodes[0].Properties
	props["collection_count"] = len(names)
	props["collections"] = names
	props["total_points"] = totalPoints
	props["points_count_unknown"] = pointsCountUnknown
	props["anonymous_listing"] = true

	// --include-points: sample payloads via POST /points/scroll.
	var scrolledResources int
	if includePoints && len(names) > 0 {
		scrolledResources = scrollAllCollections(
			ctx, client, res, opts, qdrantID, baseURL, host, port,
			names, perCollectionCap, globalCap)
		props["points_scrolled_resources"] = scrolledResources
	}

	slog.Info("qdrant loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"collections", len(names),
		"total_points", totalPoints,
		"points_count_unknown", pointsCountUnknown,
		"scrolled_resources", scrolledResources,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// fetchCollections lists collection names. Qdrant's /collections
// returns {"result":{"collections":[{"name":...}]},"status":"ok",...}.
// Parsing is defensive — a missing or empty result yields an empty
// slice, not an error (an anonymous Qdrant with zero collections is
// still a finding).
func fetchCollections(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]string, error) {
	body, err := common.GetJSON(ctx, client, strings.TrimRight(baseURL, "/")+"/collections", "", 4<<20)
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
// points_count as a nullable *int64. Qdrant's OpenAPI declares
// points_count as [integer, null] — a null/missing value must not
// conflate with a real 0. The caller aggregates only non-nil values
// into total_points and tracks the null count separately.
func fetchCollectionPoints(ctx context.Context, client *http.Client, baseURL, name string) (*int64, error) {
	u := strings.TrimRight(baseURL, "/") + "/collections/" + url.PathEscape(name)
	body, err := common.GetJSON(ctx, client, u, "", 4<<20)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Result struct {
			PointsCount *int64 `json:"points_count"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode /collections/%s: %w", name, err)
	}
	return parsed.Result.PointsCount, nil
}

// scrollAllCollections runs the POST /points/scroll probe for every
// collection under a global emission cap. Returns the total number of
// :MCPResource nodes emitted.
//
// Each collection scrolls up to perCollectionCap points, paginating
// via result.next_page_offset until null (or the caps are hit). An
// atomic counter guards the global cap so workers stop cleanly.
func scrollAllCollections(
	ctx context.Context,
	client *http.Client,
	res *action.LootResult,
	opts action.LootOptions,
	qdrantID, baseURL, host string,
	port int,
	names []string,
	perCollectionCap, globalCap int,
) int {
	var (
		globalCount atomic.Int64
		mu          sync.Mutex
	)
	globalCap64 := int64(globalCap)

	conc := DefaultCollectionConcurrency
	if conc > len(names) {
		conc = len(names)
	}
	idxs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idxs {
				// Global cap check BEFORE starting the scroll: no
				// point beginning a page if we've already hit the cap.
				remaining := globalCap64 - globalCount.Load()
				if remaining <= 0 {
					slog.Info("qdrant loot: global points cap reached; skipping remaining scrolls",
						"collection", names[i],
						"engagement_id", opts.EngagementID,
						"cap", globalCap)
					continue
				}
				perColl := perCollectionCap
				if int64(perColl) > remaining {
					perColl = int(remaining)
				}
				resources, err := fetchScrolledPoints(
					ctx, client, baseURL, host, port, qdrantID, names[i], perColl, opts.EngagementID)
				if err != nil {
					mu.Lock()
					res.PartialErrors = append(res.PartialErrors,
						fmt.Sprintf("collections/%s/points/scroll: %v", names[i], err))
					res.Summary.PartialFailures++
					mu.Unlock()
					continue
				}
				if len(resources) == 0 {
					continue
				}
				mu.Lock()
				for _, pr := range resources {
					// Re-check the cap under the mutex — another
					// worker may have emitted since we sized perColl.
					if globalCount.Load() >= globalCap64 {
						break
					}
					res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, pr.node)
					res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, pr.edge)
					globalCount.Add(1)
				}
				mu.Unlock()
			}
		}()
	}
	for i := range names {
		idxs <- i
	}
	close(idxs)
	wg.Wait()
	return int(globalCount.Load())
}

// pointResource pairs an :MCPResource node with its PROVIDES_RESOURCE
// edge for atomic append by the scroll orchestrator.
type pointResource struct {
	node ingest.Node
	edge ingest.Edge
}

// fetchScrolledPoints POSTs /collections/{name}/points/scroll,
// iterating result.next_page_offset until null OR perCollectionCap is
// reached. Returns one pointResource per point.
func fetchScrolledPoints(
	ctx context.Context,
	client *http.Client,
	baseURL, host string,
	port int,
	qdrantID, collection string,
	perCollectionCap int,
	engagementID string,
) ([]pointResource, error) {
	if perCollectionCap <= 0 {
		return nil, nil
	}
	scrollURL := strings.TrimRight(baseURL, "/") + "/collections/" + url.PathEscape(collection) + "/points/scroll"

	var out []pointResource
	var nextOffset json.RawMessage // opaque per Qdrant OpenAPI (anyOf integer|string|uuid)

	for {
		remaining := perCollectionCap - len(out)
		if remaining <= 0 {
			break
		}
		limit := scrollPageLimit
		if limit > remaining {
			limit = remaining
		}
		body := map[string]any{
			"limit":        limit,
			"with_payload": true,
			"with_vector":  false,
		}
		if len(nextOffset) > 0 && string(nextOffset) != "null" {
			body["offset"] = nextOffset
		}
		payload, _ := json.Marshal(body)

		respBody, err := postJSON(ctx, client, scrollURL, payload)
		if err != nil {
			if len(out) == 0 {
				return nil, err
			}
			return out, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			Result struct {
				Points []struct {
					ID      json.RawMessage `json:"id"`
					Payload json.RawMessage `json:"payload"`
				} `json:"points"`
				NextPageOffset json.RawMessage `json:"next_page_offset"`
			} `json:"result"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return out, fmt.Errorf("decode scroll: %w", err)
		}
		for _, p := range parsed.Result.Points {
			pointID := formatPointID(p.ID)
			if pointID == "" {
				continue
			}
			uri := fmt.Sprintf("qdrant://%s:%d/%s/%s", host, port, collection, pointID)
			resourceID := ingest.ComputeNodeID("MCPResource", qdrantID, uri)
			node := ingest.Node{
				ID:    resourceID,
				Kinds: []string{"MCPResource"},
				Properties: map[string]any{
					"objectid":    resourceID,
					"uri":         uri,
					"name":        collection + "/" + pointID,
					"mime_type":   "application/json",
					"uri_scheme":  "qdrant",
					"sensitivity": "high",
				},
			}
			edge := ingest.Edge{
				Source:     qdrantID,
				Target:     resourceID,
				Kind:       "PROVIDES_RESOURCE",
				SourceKind: "QdrantInstance",
				TargetKind: "MCPResource",
				Properties: map[string]any{
					"confidence":  1.0,
					"risk_weight": 0.2,
					"evidence": map[string]any{
						"endpoint":      baseURL,
						"source":        "points_scroll",
						"engagement_id": engagementID,
						"collection":    collection,
						"point_id":      pointID,
					},
				},
			}
			out = append(out, pointResource{node: node, edge: edge})
			if len(out) >= perCollectionCap {
				break
			}
		}
		// Terminal: next_page_offset is JSON null / absent / empty.
		if len(parsed.Result.NextPageOffset) == 0 ||
			string(parsed.Result.NextPageOffset) == "null" ||
			len(parsed.Result.Points) == 0 {
			break
		}
		nextOffset = parsed.Result.NextPageOffset
	}
	return out, nil
}

// formatPointID renders a Qdrant point ID (integer or UUID/string) as
// a URL-safe string component.
func formatPointID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	s := strings.TrimSpace(string(raw))
	// String IDs come in quoted; unquote to a plain token.
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var unquoted string
		if err := json.Unmarshal(raw, &unquoted); err == nil {
			return url.PathEscape(unquoted)
		}
	}
	// Integer IDs (unquoted) come through as decimal strings — safe.
	return s
}

// postJSON issues a POST with a JSON body and returns the response
// body on 2xx. Extracted here (rather than sdk/common) because
// qdrantloot is the only Looter beyond mlflowloot that needs a
// non-GET path.
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
var _ interface {
	RegisterFlags(*pflag.FlagSet)
} = (*Looter)(nil)

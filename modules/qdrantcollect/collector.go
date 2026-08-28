// Package qdrantcollect implements the Qdrant Collector.
//
// Qdrant is a vector database commonly fronted by LLM/RAG systems
// (default port 6333, REST API). By default Qdrant has NO auth, so the
// collection inventory and per-collection statistics are readable
// anonymously. The Collector surfaces:
//
//	GET  /collections                            — list collection names
//	GET  /collections/{name}                     — per-collection details (points_count, etc.)
//	POST /collections/{name}/points/scroll       — paginated payload sampling (opt-in)
//
// The GET-only default has ONE POST exception: /points/scroll, which
// Qdrant's OpenAPI exposes only via POST. It is idempotent and
// read-only-in-effect (returns points + payload, no state change),
// documented at openapi.json ScrollRequest:10273 / ScrollResult:10411.
// The collector runs it only under the fixed deep-scan preset.
//
// Each collection is represented once as :VectorCollection and joined to its
// QdrantInstance via PROVIDES_RESOURCE. Deep mode records only bounded sample
// counts on that collection; individual vector points never become graph
// nodes.
package qdrantcollect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

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
	// /points/scroll per collection under the deep preset.
	DefaultPointsPerCollection = 100

	// DefaultMaxTotalResources caps the global number of points sampled across
	// all collections. It bounds work without expanding graph cardinality.
	DefaultMaxTotalResources = 5000

	// scrollPageLimit is the per-request limit sent to /points/scroll.
	// Qdrant returns points + next_page_offset; we iterate until
	// next_page_offset is null OR per-collection cap OR global cap.
	scrollPageLimit = 256
)

// Collector is the registered module.
type Collector struct{}

// Collect probes a Qdrant REST API anonymously, listing collections and
// their per-collection point counts, then folds an inventory summary
// onto the existing QdrantInstance node and emits one VectorCollection per
// collection. Deep mode additionally records bounded point-sampling summaries.
//
// opts.Extras keys consumed by this Collector:
//
//	"include-points"         bool  — gate POST /points/scroll
//	"points-per-collection"  int   — per-collection sampling cap
//	"max-total-resources"    int   — global cap across all collections
func (l *Collector) Collect(ctx context.Context, t action.Target, opts action.CollectOptions) (*action.CollectResult, error) {
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL, err := action.CanonicalEndpointIdentity(t, DefaultPort, "http")
	if err != nil {
		return nil, fmt.Errorf("qdrant collection: canonical endpoint: %w", err)
	}
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

	res := &action.CollectResult{
		IngestData: &ingest.IngestData{},
		Inventory: &action.InventoryResult{
			Name: "collections", State: ingest.OutcomeFailed,
		},
	}

	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    qdrantID,
		Kinds: []string{"QdrantInstance", "AIService"},
		Properties: map[string]any{
			"objectid":            qdrantID,
			"endpoint":            baseURL,
			"name":                host,
			"collection_observed": true,
			"service_kind":        "qdrant",
		},
	})
	res.Summary.EndpointsProbed++

	names, truncated, err := fetchCollections(ctx, client, baseURL, maxItems)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("qdrant collection: /collections failed",
			"endpoint", baseURL,
			"error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("collections: %v", err))
		res.Summary.PartialFailures++
		res.Inventory.Error = res.PartialErrors[len(res.PartialErrors)-1]
		return res, nil
	}
	markAnonymousInventorySuccess(res.IngestData.Graph.Nodes[0].Properties)

	sort.Strings(names)
	res.Inventory.Items = len(names)
	res.Inventory.State = ingest.OutcomeComplete
	if truncated {
		message := fmt.Sprintf("collections: truncated at max_items=%d", maxItems)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		res.Inventory.State = ingest.OutcomeTruncated
		res.Inventory.Error = message
	}

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
			slog.Debug("qdrant collection: collection detail failed",
				"collection", names[i],
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

	collectionNodeIndex := make(map[string]int, len(names))
	lastSeen := time.Now().UTC().Format(time.RFC3339)
	for i, name := range names {
		collectionID := ingest.ComputeNodeID("VectorCollection", qdrantID, name)
		collectionProps := map[string]any{
			"objectid": collectionID, "name": name,
			"sensitivity": "high", "inventory_observed": true,
		}
		if detErrs[i] == "" && points[i] != nil {
			collectionProps["point_count"] = *points[i]
		}
		collectionNodeIndex[name] = len(res.IngestData.Graph.Nodes)
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID: collectionID, Kinds: []string{"VectorCollection"}, Properties: collectionProps,
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, ingest.Edge{
			Source: qdrantID, Target: collectionID, Kind: "PROVIDES_RESOURCE",
			SourceKind: "QdrantInstance", TargetKind: "VectorCollection",
			Properties: map[string]any{
				"confidence": 1.0, "risk_weight": 0.2,
				"evidence_state": string(ingest.EvidenceVerified), "last_seen": lastSeen,
				"evidence": map[string]any{
					"endpoint": baseURL, "source": "collections", "collection": name,
				},
			},
		})
	}

	// Deep mode samples payloads via POST /points/scroll.
	var sampledPoints int
	if includePoints && len(names) > 0 {
		samples := scrollAllCollections(
			ctx, client, res, baseURL, names, perCollectionCap, globalCap,
		)
		for i, sample := range samples {
			sampledPoints += sample.Count
			node := &res.IngestData.Graph.Nodes[collectionNodeIndex[names[i]]]
			node.Properties["sampled_point_count"] = sample.Count
			node.Properties["sample_complete"] = sample.Complete
			node.Properties["sample_limit"] = perCollectionCap
		}
		props["points_sampled"] = sampledPoints
	}

	slog.Info("qdrant collection complete",
		"endpoint", baseURL,
		"collections", len(names),
		"total_points", totalPoints,
		"points_count_unknown", pointsCountUnknown,
		"sampled_points", sampledPoints,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// fetchCollections lists collection names. Qdrant's /collections
// returns {"result":{"collections":[{"name":...}]},"status":"ok",...}.
// Parsing is defensive — a missing or empty result yields an empty
// slice, not an error (an anonymous Qdrant with zero collections is
// still a finding).
func fetchCollections(ctx context.Context, client *http.Client, baseURL string, maxItems int) ([]string, bool, error) {
	body, err := common.GetJSON(ctx, client, strings.TrimRight(baseURL, "/")+"/collections", "", 4<<20)
	if err != nil {
		return nil, false, err
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Status string          `json:"status"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, fmt.Errorf("decode /collections: %w", err)
	}
	resultJSON := bytes.TrimSpace(envelope.Result)
	if envelope.Status != "ok" || len(resultJSON) == 0 || resultJSON[0] != '{' {
		return nil, false, errors.New("decode /collections: expected an ok result object")
	}
	var result struct {
		Collections json.RawMessage `json:"collections"`
	}
	if err := json.Unmarshal(resultJSON, &result); err != nil {
		return nil, false, fmt.Errorf("decode /collections result: %w", err)
	}
	collectionsJSON := bytes.TrimSpace(result.Collections)
	if len(collectionsJSON) == 0 || collectionsJSON[0] != '[' {
		return nil, false, errors.New("decode /collections: expected a collections array")
	}
	var collections []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(collectionsJSON, &collections); err != nil {
		return nil, false, fmt.Errorf("decode /collections array: %w", err)
	}
	out := make([]string, 0, len(collections))
	for _, c := range collections {
		if c.Name == "" {
			continue
		}
		out = append(out, c.Name)
		if len(out) >= maxItems {
			break
		}
	}
	return out, len(collections) > len(out), nil
}

func markAnonymousInventorySuccess(props map[string]any) {
	props["auth_method"] = string(common.AuthNone)
	props["auth_assurance"] = string(common.AuthAssuranceUnauthenticated)
	props["auth_evidence"] = common.AuthEvidenceAnonymousProbeSucceeded
	props["probe_status"] = string(common.VerificationVerified)
	props["last_verified_at"] = time.Now().UTC().Format(time.RFC3339)
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

type pointSampleSummary struct {
	Count    int
	Complete bool
}

// scrollAllCollections runs the bounded POST /points/scroll read for each
// collection and returns summaries in the same order as names.
func scrollAllCollections(
	ctx context.Context,
	client *http.Client,
	res *action.CollectResult,
	baseURL string,
	names []string,
	perCollectionCap, globalCap int,
) []pointSampleSummary {
	var mu sync.Mutex
	globalCount := 0
	summaries := make([]pointSampleSummary, len(names))

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
				mu.Lock()
				remaining := globalCap - globalCount
				mu.Unlock()
				if remaining <= 0 {
					slog.Info("qdrant collection: global points cap reached; skipping remaining scrolls",
						"collection", names[i],
						"cap", globalCap)
					continue
				}
				perColl := perCollectionCap
				if perColl > remaining {
					perColl = remaining
				}
				summary, err := fetchScrolledPointSummary(
					ctx, client, baseURL, names[i], perColl,
				)
				mu.Lock()
				accepted := summary.Count
				if accepted > globalCap-globalCount {
					accepted = globalCap - globalCount
					summary.Complete = false
				}
				if accepted < 0 {
					accepted = 0
				}
				summary.Count = accepted
				summaries[i] = summary
				globalCount += accepted
				if err != nil {
					res.PartialErrors = append(res.PartialErrors,
						fmt.Sprintf("collections/%s/points/scroll: %v", names[i], err))
					res.Summary.PartialFailures++
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
	return summaries
}

func fetchScrolledPointSummary(
	ctx context.Context,
	client *http.Client,
	baseURL, collection string,
	perCollectionCap int,
) (pointSampleSummary, error) {
	if perCollectionCap <= 0 {
		return pointSampleSummary{}, nil
	}
	scrollURL := strings.TrimRight(baseURL, "/") + "/collections/" + url.PathEscape(collection) + "/points/scroll"

	summary := pointSampleSummary{}
	var nextOffset json.RawMessage // opaque per Qdrant OpenAPI (anyOf integer|string|uuid)

	for {
		remaining := perCollectionCap - summary.Count
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
			return summary, fmt.Errorf("page: %w", err)
		}
		var parsed struct {
			Result struct {
				Points         []json.RawMessage `json:"points"`
				NextPageOffset json.RawMessage   `json:"next_page_offset"`
			} `json:"result"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return summary, fmt.Errorf("decode scroll: %w", err)
		}
		count := len(parsed.Result.Points)
		if count > remaining {
			count = remaining
		}
		summary.Count += count
		// Terminal: next_page_offset is JSON null / absent / empty.
		if len(parsed.Result.NextPageOffset) == 0 ||
			string(parsed.Result.NextPageOffset) == "null" ||
			len(parsed.Result.Points) == 0 {
			summary.Complete = true
			break
		}
		nextOffset = parsed.Result.NextPageOffset
	}
	return summary, nil
}

// postJSON issues a POST with a JSON body and returns the response
// body on 2xx. Extracted here (rather than sdk/common) because
// qdrantcollect is the only Collector beyond mlflowcollect that needs a
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

var _ action.ServiceCollector = (*Collector)(nil)

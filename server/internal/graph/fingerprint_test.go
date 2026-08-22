package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	configcollector "github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/modules/litellmcollect"
	"github.com/adithyan-ak/agenthound/modules/openwebuicollect"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestObservationFactFingerprintIgnoresWriterLifecycleFields(t *testing.T) {
	const domain = "config:path:sha256:fingerprint"
	left, err := observationFactFingerprints([]string{domain}, map[string]any{
		"properties": fingerprintProperties(map[string]any{
			"endpoint":            "http://mcp.example/mcp",
			"scan_id":             "scan-one",
			"last_seen":           "one",
			"last_verified_at":    "2026-07-19T01:00:00Z",
			"observed_content_at": "2026-07-19T01:00:00Z",
			"extracted_at":        "2026-07-19T01:00:00Z",
		}),
	})
	if err != nil {
		t.Fatalf("left fingerprint: %v", err)
	}
	right, err := observationFactFingerprints([]string{domain}, map[string]any{
		"properties": fingerprintProperties(map[string]any{
			"last_seen":           "two",
			"scan_id":             "scan-two",
			"endpoint":            "http://mcp.example/mcp",
			"last_verified_at":    "2026-07-19T02:00:00Z",
			"observed_content_at": "2026-07-19T02:00:00Z",
			"extracted_at":        "2026-07-19T02:00:00Z",
		}),
	})
	if err != nil {
		t.Fatalf("right fingerprint: %v", err)
	}
	if len(left) != 1 || len(right) != 1 || left[0] != right[0] {
		t.Fatalf("volatile lifecycle fields changed fingerprint: left=%q right=%q", left, right)
	}
	if !strings.HasPrefix(left[0], domain+observationFactFingerprintSeparator) {
		t.Fatalf("fingerprint %q is not scoped to domain %q", left[0], domain)
	}
}

func TestObservationOwnerFingerprintsPairDomainsWithFacts(t *testing.T) {
	const (
		domainA = "config:path:sha256:owner-a"
		domainB = "config:path:sha256:owner-b"
	)
	fingerprints, err := observationFactFingerprints(
		[]string{domainB, domainA},
		map[string]any{"properties": map[string]any{"endpoint": "stdio://server"}},
	)
	if err != nil {
		t.Fatalf("fingerprints: %v", err)
	}
	owners := observationOwnerFingerprints(
		[]string{domainB, domainA, domainA},
		fingerprints,
	)
	want := []map[string]any{
		{
			"token_prefix":     observationDomainPrefix(domainA),
			"fact_fingerprint": fingerprints[0],
		},
		{
			"token_prefix":     observationDomainPrefix(domainB),
			"fact_fingerprint": fingerprints[1],
		},
	}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("owner fingerprints = %#v, want %#v", owners, want)
	}

	missing := observationOwnerFingerprints(
		[]string{domainA, domainB},
		fingerprints[:1],
	)
	if len(missing) != 1 {
		t.Fatalf("missing owner fingerprint was fabricated: %#v", missing)
	}
}

func TestPrepareObservationNodesFingerprintsOwnersBeforeUnion(t *testing.T) {
	const (
		domainA = "config:path:sha256:owner-a"
		domainB = "mcp:target:sha256:owner-b"
	)
	nodes := []ingest.Node{
		{
			ID: "shared", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{domainA},
			Properties: map[string]any{
				"objectid":         "shared",
				"endpoint":         "https://mcp.example/mcp",
				"configured_name":  "configured",
				"last_verified_at": "2026-07-19T01:00:00Z",
			},
		},
		{
			ID: "shared", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{domainB},
			Properties: map[string]any{
				"objectid":         "shared",
				"endpoint":         "https://mcp.example/mcp",
				"protocol_version": "2025-06-18",
				"last_verified_at": "2026-07-19T02:00:00Z",
			},
		},
	}

	prepared, fingerprints, err := prepareObservationNodes(nodes)
	if err != nil {
		t.Fatalf("prepare nodes: %v", err)
	}
	if len(prepared) != 1 {
		t.Fatalf("prepared rows = %d, want one final authoritative row", len(prepared))
	}
	wantDomains := []string{domainA, domainB}
	if !reflect.DeepEqual(prepared[0].ObservationDomains, wantDomains) {
		t.Fatalf("domains = %v, want %v", prepared[0].ObservationDomains, wantDomains)
	}
	if prepared[0].Properties["configured_name"] != "configured" ||
		prepared[0].Properties["protocol_version"] != "2025-06-18" ||
		prepared[0].Properties["last_verified_at"] != "2026-07-19T02:00:00Z" {
		t.Fatalf("union properties = %#v", prepared[0].Properties)
	}
	gotFingerprints := fingerprints[nodePreparationKey(prepared[0])]
	if len(gotFingerprints) != 2 || gotFingerprints[0] == gotFingerprints[1] {
		t.Fatalf("owner fingerprints = %v, want two distinct pre-union facts", gotFingerprints)
	}
	if !strings.HasPrefix(gotFingerprints[0], domainA+observationFactFingerprintSeparator) ||
		!strings.HasPrefix(gotFingerprints[1], domainB+observationFactFingerprintSeparator) {
		t.Fatalf("fingerprints are not stably domain-scoped: %v", gotFingerprints)
	}

	reversed := []ingest.Node{nodes[1], nodes[0]}
	reversedPrepared, reversedFingerprints, err := prepareObservationNodes(reversed)
	if err != nil {
		t.Fatalf("prepare reversed nodes: %v", err)
	}
	if !reflect.DeepEqual(prepared, reversedPrepared) ||
		!reflect.DeepEqual(fingerprints, reversedFingerprints) {
		t.Fatalf(
			"node preparation depends on input order:\nforward=%#v %#v\nreverse=%#v %#v",
			prepared, fingerprints, reversedPrepared, reversedFingerprints,
		)
	}
}

func TestPrepareObservationNodesAcceptsSharedConfigCredential(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	firstPath := filepath.Join(tmp, "cursor.json")
	secondPath := filepath.Join(tmp, "vscode.json")
	const shared = "writer-shared-credential-material"
	for path, contents := range map[string]string{
		firstPath:  `{"mcpServers":{"cursor-server":{"url":"https://cursor.example/mcp","headers":{"Authorization":"Bearer ` + shared + `"}}}}`,
		secondPath: `{"mcpServers":{"vscode-server":{"url":"https://vscode.example/mcp","headers":{"X-API-Key":"` + shared + `"}}}}`,
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write config %s: %v", path, err)
		}
	}

	data, err := configcollector.NewConfigCollector().Collect(context.Background(), collector.CollectOptions{
		ConfigPaths: []string{firstPath, secondPath}, ProjectDir: tmp, ScanID: "shared-credential-writer-test",
	})
	if err != nil {
		t.Fatalf("collect configs: %v", err)
	}
	prepared, _, err := prepareObservationNodes(data.Graph.Nodes)
	if err != nil {
		t.Fatalf("prepare shared credential: %v", err)
	}

	wantHash := common.HashCredentialValue(shared)
	credentials := 0
	for _, node := range prepared {
		if ingest.ConcreteNodeKind(node.Kinds) == "Credential" && node.Properties["value_hash"] == wantHash {
			credentials++
			if got, want := node.Properties["sources"], []string{"cursor-server", "vscode-server"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("prepared credential sources = %#v, want %#v", got, want)
			}
		}
	}
	if credentials != 1 {
		t.Fatalf("prepared shared credentials = %d, want one", credentials)
	}
}

func TestPrepareObservationNodesAcceptsDistinctLiteLLMMasterCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/model/info":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/key/list":
			_, _ = w.Write([]byte(`{"keys":[],"total_count":0,"total_pages":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	target := action.Target{
		Kind: "host", Address: strings.TrimPrefix(server.URL, "http://"),
	}
	const domain = "scan:loot:sha256:litellm-multi-credential"
	var nodes []ingest.Node
	for _, key := range []string{
		"sk-first-litellm-master-key",
		"sk-second-litellm-master-key",
		"sk-third-litellm-master-key",
	} {
		result, err := (&litellmcollect.Collector{}).Collect(
			context.Background(), target, action.CollectOptions{
				Credentials: map[string]string{"master_key": key},
			},
		)
		if err != nil {
			t.Fatalf("collect with key %q: %v", key, err)
		}
		graph := result.IngestData.Graph
		ingest.TagObservationDomain(&graph, domain)
		nodes = append(nodes, graph.Nodes...)
	}

	prepared, _, err := prepareObservationNodes(nodes)
	if err != nil {
		t.Fatalf("writer preparation rejected distinct LiteLLM credentials: %v", err)
	}
	credentialIDs := make(map[string]bool)
	for _, node := range prepared {
		if ingest.ConcreteNodeKind(node.Kinds) == "Credential" && node.Properties["type"] == "master_key" {
			credentialIDs[node.ID] = true
		}
	}
	if len(credentialIDs) != 3 {
		t.Fatalf("prepared LiteLLM master credential IDs = %v, want three", credentialIDs)
	}
}

func TestPrepareObservationNodesAcceptsRepeatedOpenWebUIPosture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/api/config" {
			_, _ = w.Write([]byte(
				`{"status":true,"features":{"auth":true,"enable_signup":false}}`,
			))
			return
		}
		if request.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	target := action.Target{
		Kind: "host", Address: strings.TrimPrefix(server.URL, "http://"),
	}
	const domain = "scan:loot:sha256:openwebui-multi-credential"
	var nodes []ingest.Node
	for _, key := range []string{"", "sk-first-openwebui-key", "sk-second-openwebui-key"} {
		opts := action.CollectOptions{}
		if key != "" {
			opts.Credentials = map[string]string{"api_key": key}
		}
		result, err := (&openwebuicollect.Collector{}).Collect(context.Background(), target, opts)
		if err != nil {
			t.Fatalf("collect with key %q: %v", key, err)
		}
		graph := result.IngestData.Graph
		ingest.TagObservationDomain(&graph, domain)
		nodes = append(nodes, graph.Nodes...)
	}

	prepared, _, err := prepareObservationNodes(nodes)
	if err != nil {
		t.Fatalf("writer preparation rejected repeated OpenWebUI posture: %v", err)
	}
	instances := 0
	for _, node := range prepared {
		if ingest.ConcreteNodeKind(node.Kinds) != "OpenWebUIInstance" {
			continue
		}
		instances++
		if node.Properties["auth_method"] != string(common.AuthUnknown) ||
			node.Properties["auth_evidence"] != common.AuthEvidenceUnknown {
			t.Fatalf("prepared OpenWebUI posture = %+v, want stable protected unknown", node.Properties)
		}
	}
	if instances != 1 {
		t.Fatalf("prepared OpenWebUI instances = %d, want one", instances)
	}
}

func TestPrepareObservationNodesRejectsConflictsBeforeExecution(t *testing.T) {
	const (
		domainA = "config:path:sha256:conflict-a"
		domainB = "mcp:target:sha256:conflict-b"
	)
	nodes := []ingest.Node{
		{
			ID: "shared", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{domainA},
			Properties:         map[string]any{"endpoint": "https://one.example/mcp"},
		},
		{
			ID: "shared", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{domainB},
			Properties:         map[string]any{"endpoint": "https://two.example/mcp"},
		},
	}
	_, _, forwardErr := prepareObservationNodes(nodes)
	_, _, reverseErr := prepareObservationNodes([]ingest.Node{nodes[1], nodes[0]})
	if forwardErr == nil || reverseErr == nil || forwardErr.Error() != reverseErr.Error() {
		t.Fatalf("order-dependent conflict: forward=%v reverse=%v", forwardErr, reverseErr)
	}
	if !strings.Contains(forwardErr.Error(), `property "endpoint"`) {
		t.Fatalf("conflict does not identify property: %v", forwardErr)
	}

	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	if _, err := writer.WriteObservationNodes(
		context.Background(), nodes, "conflict-scan", []string{domainA, domainB},
	); err == nil {
		t.Fatal("writer accepted conflicting owner properties")
	}
	if calls := recorder.snapshot(); len(calls) != 0 {
		t.Fatalf("conflicting contributions reached Neo4j execution: %+v", calls)
	}
}

func TestPrepareObservationNodesKeepsLatestObservedContentTimestamp(t *testing.T) {
	const domain = "mcp:target:sha256:observed-content"
	nodes := []ingest.Node{
		{
			ID: "resource", Kinds: []string{"MCPResource"},
			ObservationDomains: []string{domain},
			Properties: map[string]any{
				"observed_content":    "same content",
				"observed_content_at": "2026-08-19T22:00:00Z",
			},
		},
		{
			ID: "resource", Kinds: []string{"MCPResource"},
			ObservationDomains: []string{domain},
			Properties: map[string]any{
				"observed_content":    "same content",
				"observed_content_at": "2026-08-19T22:00:01Z",
			},
		},
	}

	prepared, _, err := prepareObservationNodes(nodes)
	if err != nil {
		t.Fatalf("prepare nodes: %v", err)
	}
	if len(prepared) != 1 ||
		prepared[0].Properties["observed_content_at"] != "2026-08-19T22:00:01Z" {
		t.Fatalf("prepared nodes = %#v, want latest observation timestamp", prepared)
	}
}

func TestPrepareObservationFragmentsRejectSameOwnerConflicts(t *testing.T) {
	const domain = "mcp:target:sha256:same-owner-conflict"
	nodes := []ingest.Node{
		{
			ID: "shared", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{domain},
			Properties:         map[string]any{"name": "first"},
		},
		{
			ID: "shared", Kinds: []string{"MCPServer"},
			ObservationDomains: []string{domain},
			Properties:         map[string]any{"name": "second"},
		},
	}
	if _, _, err := prepareObservationNodes(nodes); err == nil ||
		!strings.Contains(err.Error(), `property "name"`) {
		t.Fatalf("same-owner node conflict = %v", err)
	}

	edges := []ingest.Edge{
		{
			Source: "server", Kind: "RUNS_ON", Target: "host",
			SourceKind: "MCPServer", TargetKind: "Host",
			ObservationDomains: []string{domain},
			Properties:         map[string]any{"confidence": 1.0},
		},
		{
			Source: "server", Kind: "RUNS_ON", Target: "host",
			SourceKind: "MCPServer", TargetKind: "Host",
			ObservationDomains: []string{domain},
			Properties:         map[string]any{"confidence": 0.5},
		},
	}
	if _, _, err := prepareObservationEdges(edges); err == nil ||
		!strings.Contains(err.Error(), `property "confidence"`) {
		t.Fatalf("same-owner edge conflict = %v", err)
	}
}

func TestWriterCoalescesRowsButKeepsReferenceSemanticsSeparate(t *testing.T) {
	const (
		authoritativeDomain = "config:path:sha256:authoritative"
		referenceDomain     = "scan:loot:sha256:reference"
	)
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	written, err := writer.WriteObservationNodes(
		context.Background(),
		[]ingest.Node{
			{
				ID: "shared", Kinds: []string{"MCPServer"},
				ObservationDomains: []string{authoritativeDomain},
				Properties:         map[string]any{"endpoint": "https://mcp.example/mcp"},
			},
			{
				ID: "shared", Kinds: []string{"MCPServer"},
				ObservationDomains: []string{referenceDomain},
				PropertySemantics:  ingest.NodePropertySemanticsReferenceOnly,
				Properties:         map[string]any{"objectid": "shared"},
			},
		},
		"shared-semantics",
		[]string{authoritativeDomain, referenceDomain},
	)
	if err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	if written != 1 {
		t.Fatalf("unique node write rows = %d, want 1", written)
	}
	calls := recorder.snapshot()
	if len(calls) != 2 {
		t.Fatalf("execution groups = %d, want separate authoritative/reference rows", len(calls))
	}
	var authoritative, reference int
	for _, call := range calls {
		for _, row := range rowsAt(t, call.Params, "nodes") {
			if referenceOnly, _ := row["reference_only"].(bool); referenceOnly {
				reference++
			} else {
				authoritative++
			}
		}
	}
	if authoritative != 1 || reference != 1 {
		t.Fatalf("execution rows: authoritative=%d reference=%d", authoritative, reference)
	}
}

func TestWriterEdgePreparationMatchesAPOCAndFallback(t *testing.T) {
	const (
		domainA = "config:path:sha256:edge-a"
		domainB = "mcp:target:sha256:edge-b"
	)
	edges := []ingest.Edge{
		{
			Source: "server", Kind: "RUNS_ON", Target: "host",
			SourceKind: "MCPServer", TargetKind: "Host",
			ObservationDomains: []string{domainA},
			Properties: map[string]any{
				"confidence":       1.0,
				"last_verified_at": "2026-07-19T01:00:00Z",
			},
		},
		{
			Source: "server", Kind: "RUNS_ON", Target: "host",
			SourceKind: "MCPServer", TargetKind: "Host",
			ObservationDomains: []string{domainB},
			Properties: map[string]any{
				"risk_weight":      0.0,
				"last_verified_at": "2026-07-19T02:00:00Z",
			},
		},
	}

	sharedRows := make(map[bool]map[string]any)
	for _, hasAPOC := range []bool{false, true} {
		recorder := &recordedExec{}
		writer := newTestWriter(recorder.exec, hasAPOC)
		written, err := writer.WriteObservationEdges(
			context.Background(), edges, "edge-scan", []string{domainA, domainB},
		)
		if err != nil {
			t.Fatalf("write edges (APOC=%t): %v", hasAPOC, err)
		}
		if written != 1 {
			t.Fatalf("unique edge rows (APOC=%t) = %d, want 1", hasAPOC, written)
		}
		calls := recorder.snapshot()
		if len(calls) != 1 {
			t.Fatalf("calls (APOC=%t) = %d", hasAPOC, len(calls))
		}
		if !reflect.DeepEqual(
			calls[0].Params["semantic_volatile_properties"],
			observationVolatilePropertyKeys,
		) {
			t.Fatalf("volatile params (APOC=%t) = %#v", hasAPOC, calls[0].Params)
		}
		if !strings.Contains(
			calls[0].Cypher,
			"WHEN incoming_authoritative THEN\n        [fingerprint IN old_fact_fingerprints",
		) {
			t.Fatalf("incompatible-refresh invalidation missing (APOC=%t):\n%s", hasAPOC, calls[0].Cypher)
		}
		row := rowsAt(t, calls[0].Params, "edges")[0]
		fingerprints, ok := row["observation_fact_fingerprints"].([]string)
		if !ok || len(fingerprints) != 2 || fingerprints[0] == fingerprints[1] {
			t.Fatalf("edge fingerprints (APOC=%t) = %#v", hasAPOC, row["observation_fact_fingerprints"])
		}
		properties := propsAt(t, row, "properties")
		if properties["confidence"] != 1.0 || properties["risk_weight"] != 0.0 ||
			properties["last_verified_at"] != "2026-07-19T02:00:00Z" {
			t.Fatalf("edge union (APOC=%t) = %#v", hasAPOC, properties)
		}
		delete(row, "create_properties")
		sharedRows[hasAPOC] = row
	}
	if !reflect.DeepEqual(sharedRows[false], sharedRows[true]) {
		t.Fatalf("APOC/fallback semantic rows differ:\nfallback=%#v\nAPOC=%#v", sharedRows[false], sharedRows[true])
	}
}

func TestPrepareObservationEdgesRejectsConflictsDeterministically(t *testing.T) {
	const (
		domainA = "config:path:sha256:edge-conflict-a"
		domainB = "mcp:target:sha256:edge-conflict-b"
	)
	edges := []ingest.Edge{
		{
			Source: "server", Kind: "RUNS_ON", Target: "host",
			SourceKind: "MCPServer", TargetKind: "Host",
			ObservationDomains: []string{domainA},
			Properties:         map[string]any{"confidence": 1.0},
		},
		{
			Source: "server", Kind: "RUNS_ON", Target: "host",
			SourceKind: "MCPServer", TargetKind: "Host",
			ObservationDomains: []string{domainB},
			Properties:         map[string]any{"confidence": 0.5},
		},
	}
	_, _, forwardErr := prepareObservationEdges(edges)
	_, _, reverseErr := prepareObservationEdges([]ingest.Edge{edges[1], edges[0]})
	if forwardErr == nil || reverseErr == nil || forwardErr.Error() != reverseErr.Error() {
		t.Fatalf("order-dependent edge conflict: forward=%v reverse=%v", forwardErr, reverseErr)
	}
	if !strings.Contains(forwardErr.Error(), `property "confidence"`) {
		t.Fatalf("edge conflict does not identify property: %v", forwardErr)
	}
}

func TestWriterCarriesStableFingerprintsForExactSharedOwnerRefresh(t *testing.T) {
	const domain = "mcp:target:sha256:fingerprint"
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	node := ingest.Node{
		ID:                 "server",
		Kinds:              []string{"MCPServer"},
		ObservationDomains: []string{domain},
		Properties: map[string]any{
			"endpoint": "http://mcp.example/mcp",
			"scan_id":  "collector-scan",
		},
	}
	if _, err := writer.WriteObservationNodes(
		context.Background(), []ingest.Node{node}, "server-scan", []string{domain},
	); err != nil {
		t.Fatalf("write node: %v", err)
	}
	call := recorder.snapshot()[0]
	row := rowsAt(t, call.Params, "nodes")[0]
	fingerprints, ok := row["observation_fact_fingerprints"].([]string)
	if !ok || len(fingerprints) != 1 ||
		!strings.HasPrefix(fingerprints[0], domain+observationFactFingerprintSeparator) {
		t.Fatalf("node fingerprints = %#v", row["observation_fact_fingerprints"])
	}
	for _, fragment := range []string{
		"compatible_existing_owner",
		"compatible_mixed_owners",
		"size(node.observation_owner_fingerprints) =",
		"owner.fact_fingerprint IN old_fact_fingerprints",
		"fingerprint IN old_fact_fingerprints",
		"WHEN compatible_existing_owner THEN true",
		"WHEN compatible_mixed_owners THEN true",
		"WHEN incoming_authoritative THEN\n        [fingerprint IN old_fact_fingerprints",
	} {
		if !strings.Contains(call.Cypher, fragment) {
			t.Fatalf("node refresh query missing %q:\n%s", fragment, call.Cypher)
		}
	}

	edgeQuery := edgeCypherForKinds("RUNS_ON", "MCPServer", "Host")
	for _, fragment := range []string{
		"compatible_existing_owner",
		"compatible_mixed_owners",
		"size(edge.observation_owner_fingerprints) =",
		"owner.fact_fingerprint IN old_fact_fingerprints",
		"edge.observation_fact_fingerprints",
		"WHEN compatible_existing_owner THEN true",
		"WHEN compatible_mixed_owners THEN true",
	} {
		if !strings.Contains(edgeQuery, fragment) {
			t.Fatalf("edge refresh query missing %q:\n%s", fragment, edgeQuery)
		}
	}
}

func TestNodeLabelMutationIsCompatibilityGated(t *testing.T) {
	query := nodeCypherForKindTuple("OllamaInstance", []string{"AIService"})
	want := "FOREACH (_ IN CASE WHEN observation_created OR replace_properties OR compatible_new_owner OR compatible_existing_owner OR compatible_mixed_owners OR partial_existing_owner OR partial_new_owner OR partial_coowner_noop OR partial_coowner_addition OR partial_reference_upgrade THEN [1] ELSE [] END | SET n:AIService)"
	if !strings.Contains(query, want) {
		t.Fatalf("extra label mutation is not compatibility-gated:\n%s", query)
	}
	if strings.Contains(query, "\nSET n:AIService") {
		t.Fatalf("query contains unconditional extra-label mutation:\n%s", query)
	}
}

func TestPublicFactPropertiesStripsInternalFingerprintWithoutMutation(t *testing.T) {
	properties := map[string]any{
		"endpoint":                     "http://mcp.example/mcp",
		"collector_note":               "observed",
		observationFactFingerprintsKey: []string{"internal"},
	}
	public := PublicFactProperties(properties)
	if public["endpoint"] != properties["endpoint"] {
		t.Fatalf("public properties lost collector data: %#v", public)
	}
	if public["collector_note"] != "observed" {
		t.Fatalf("public properties lost collector data: %#v", public)
	}
	if _, exists := public[observationFactFingerprintsKey]; exists {
		t.Fatalf("internal fingerprint leaked through public properties: %#v", public)
	}
	if _, exists := properties[observationFactFingerprintsKey]; !exists {
		t.Fatal("public sanitization mutated database property map")
	}
}

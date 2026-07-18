package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	jose "github.com/go-jose/go-jose/v4"
)

func TestCollector_Name(t *testing.T) {
	c := NewA2ACollector()
	if c.Name() != "a2a" {
		t.Errorf("expected name 'a2a', got %q", c.Name())
	}
}

func TestCollector_NoTargets(t *testing.T) {
	c := NewA2ACollector()
	_, err := c.Collect(context.Background(), collector.CollectOptions{})
	if err == nil {
		t.Fatal("expected error with no targets")
	}
}

func TestCollector_SingleTarget(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-001",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Meta.Collector != "a2a" {
		t.Errorf("expected collector 'a2a', got %q", data.Meta.Collector)
	}
	if data.Meta.ScanID != "test-scan-001" {
		t.Errorf("expected scan ID 'test-scan-001', got %q", data.Meta.ScanID)
	}

	var agentNodes, skillNodes, hostNodes, identityNodes int
	for _, n := range data.Graph.Nodes {
		for _, k := range n.Kinds {
			switch k {
			case "A2AAgent":
				agentNodes++
			case "A2ASkill":
				skillNodes++
			case "Host":
				hostNodes++
			case "Identity":
				identityNodes++
			}
		}
	}
	if agentNodes != 1 {
		t.Errorf("expected 1 A2AAgent node, got %d", agentNodes)
	}
	if skillNodes != 2 {
		t.Errorf("expected 2 A2ASkill nodes, got %d", skillNodes)
	}
	if hostNodes != 1 {
		t.Errorf("expected 1 Host node, got %d", hostNodes)
	}
	if identityNodes != 1 {
		t.Errorf("expected 1 Identity node (apiKey), got %d", identityNodes)
	}

	edgeKinds := make(map[string]int)
	for _, e := range data.Graph.Edges {
		edgeKinds[e.Kind]++
	}
	if edgeKinds["ADVERTISES_SKILL"] != 2 {
		t.Errorf("expected 2 ADVERTISES_SKILL edges, got %d", edgeKinds["ADVERTISES_SKILL"])
	}
	if edgeKinds["RUNS_ON"] != 1 {
		t.Errorf("expected 1 RUNS_ON edge, got %d", edgeKinds["RUNS_ON"])
	}
	if edgeKinds["AUTHENTICATES_WITH"] != 1 {
		t.Errorf("expected 1 AUTHENTICATES_WITH edge, got %d", edgeKinds["AUTHENTICATES_WITH"])
	}
}

func TestCollector_NoAuthAgent(t *testing.T) {
	body := loadFixture(t, "agent_card_no_auth.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-noauth",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var identityNodes int
	for _, n := range data.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "Identity" {
				identityNodes++
			}
		}
	}
	if identityNodes != 0 {
		t.Errorf("expected 0 Identity nodes for no-auth agent, got %d", identityNodes)
	}

	for _, e := range data.Graph.Edges {
		if e.Kind == "AUTHENTICATES_WITH" {
			t.Error("expected no AUTHENTICATES_WITH edge for no-auth agent")
		}
	}
}

func TestCollector_MultipleTargets(t *testing.T) {
	v030Body := loadFixture(t, "agent_card_v030.json")
	v10Body := loadFixture(t, "agent_card_v10.json")

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(v030Body)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(v10Body)
	}))
	defer srv2.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURLs: []string{srv1.URL, srv2.URL},
		ScanID:     "test-scan-multi",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var agentCount int
	for _, n := range data.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "A2AAgent" {
				agentCount++
			}
		}
	}
	if agentCount != 2 {
		t.Errorf("expected 2 A2AAgent nodes, got %d", agentCount)
	}
}

func TestCollector_A2ARelationsDeclareAllDependencies(t *testing.T) {
	cardBodies := []map[string]any{
		{
			"name":            "AgentAlpha",
			"description":     "I delegate tasks to AgentBeta for processing",
			"url":             "https://api.example.com/alpha",
			"version":         "1.0.0",
			"protocolVersion": "0.3.0",
			"securitySchemes": map[string]any{
				"oauth": map[string]any{
					"type": "oauth2",
					"flows": map[string]any{
						"clientCredentials": map[string]any{
							"tokenUrl": "https://auth.example/token",
							"scopes":   map[string]any{},
						},
					},
				},
			},
			"security": []any{map[string]any{"oauth": []any{}}},
		},
		{
			"name":            "AgentBeta",
			"description":     "Processes delegated tasks",
			"url":             "https://api.example.com/beta",
			"version":         "1.0.0",
			"protocolVersion": "0.3.0",
			"securitySchemes": map[string]any{
				"oauth": map[string]any{
					"type": "oauth2",
					"flows": map[string]any{
						"clientCredentials": map[string]any{
							"tokenUrl": "https://auth.example/token",
							"scopes":   map[string]any{},
						},
					},
				},
			},
			"security": []any{map[string]any{"oauth": []any{}}},
		},
	}
	targets := make([]string, 0, len(cardBodies))
	servers := make([]*httptest.Server, 0, len(cardBodies))
	for _, card := range cardBodies {
		body, err := json.Marshal(card)
		if err != nil {
			t.Fatalf("marshal card: %v", err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		servers = append(servers, server)
		targets = append(targets, server.URL)
	}
	for _, server := range servers {
		defer server.Close()
	}

	data, err := NewA2ACollector().Collect(context.Background(), collector.CollectOptions{
		TargetURLs: targets,
		ScanID:     "all-dependencies",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wantDomains := map[string]bool{
		a2aCoverageKey(targets[0]): true,
		a2aCoverageKey(targets[1]): true,
	}
	relationCount := 0
	for _, edge := range data.Graph.Edges {
		if edge.Kind != "DELEGATES_TO" && edge.Kind != "SAME_AUTH_DOMAIN" {
			continue
		}
		relationCount++
		if edge.ObservationSemantics != ingest.ObservationSemanticsAllDependencies {
			t.Fatalf("%s semantics = %q", edge.Kind, edge.ObservationSemantics)
		}
		if len(edge.ObservationDomains) != len(wantDomains) {
			t.Fatalf("%s domains = %v, want both card scopes", edge.Kind, edge.ObservationDomains)
		}
		for _, domain := range edge.ObservationDomains {
			if !wantDomains[domain] {
				t.Fatalf("%s has unexpected dependency domain %q", edge.Kind, domain)
			}
		}
	}
	if relationCount != 2 {
		t.Fatalf("two-card relation count = %d, want delegation and auth-domain edges: %+v", relationCount, data.Graph.Edges)
	}
}

func TestSetRelationObservationScopesUsesAnyOwnerForSameScope(t *testing.T) {
	edge := ingest.Edge{Kind: "DELEGATES_TO"}
	setRelationObservationScopes(&edge, "a2a:target:shared", "a2a:target:shared")

	if edge.ObservationSemantics != ingest.ObservationSemanticsAnyOwner {
		t.Fatalf("semantics = %q, want any_owner", edge.ObservationSemantics)
	}
	if len(edge.ObservationDomains) != 1 ||
		edge.ObservationDomains[0] != "a2a:target:shared" {
		t.Fatalf("domains = %v, want one current owner", edge.ObservationDomains)
	}
}

func TestCollector_SkipsSelfRelationsFromAliasedCards(t *testing.T) {
	cards := []map[string]any{
		{
			"name":        "AgentAlpha",
			"description": "Delegate tasks to AgentBeta",
			"url":         "https://agents.example.test/.well-known/agent.json",
			"version":     "1.0.0",
			"securitySchemes": map[string]any{
				"oauth": map[string]any{"type": "oauth2"},
			},
		},
		{
			"name":        "AgentBeta",
			"description": "Processes delegated tasks",
			"url":         "https://agents.example.test/.well-known/agent-card.json",
			"version":     "1.0.0",
			"securitySchemes": map[string]any{
				"oauth": map[string]any{"type": "oauth2"},
			},
		},
	}
	targets := make([]string, 0, len(cards))
	for _, card := range cards {
		body, err := json.Marshal(card)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		defer server.Close()
		targets = append(targets, server.URL)
	}

	data, err := NewA2ACollector().Collect(context.Background(), collector.CollectOptions{
		TargetURLs: targets,
		ScanID:     "self-relation",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, edge := range data.Graph.Edges {
		if edge.Source == edge.Target &&
			(edge.Kind == "DELEGATES_TO" || edge.Kind == "SAME_AUTH_DOMAIN") {
			t.Fatalf("collector emitted self relation: %+v", edge)
		}
	}
}

func TestBuildTargetListDeduplicatesWellKnownAliases(t *testing.T) {
	targets, err := buildTargetList(collector.CollectOptions{TargetURLs: []string{
		"https://agents.example.test/.well-known/agent.json",
		"https://agents.example.test/.well-known/agent-card.json",
	}})
	if err != nil {
		t.Fatalf("buildTargetList: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %v, want one canonical well-known target", targets)
	}
}

func TestCollector_TargetURLsFile(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	urlsFile := filepath.Join(tmpDir, "targets.txt")
	content := "# Test targets file\n" + srv.URL + "\n\n# Another comment\n"
	if err := os.WriteFile(urlsFile, []byte(content), 0644); err != nil {
		t.Fatalf("write urls file: %v", err)
	}

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURLsFile: urlsFile,
		ScanID:         "test-scan-file",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var agentCount int
	for _, n := range data.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "A2AAgent" {
				agentCount++
			}
		}
	}
	if agentCount != 1 {
		t.Errorf("expected 1 A2AAgent node, got %d", agentCount)
	}
}

func TestCollector_FailedTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-fail",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Graph.Nodes) != 0 {
		t.Errorf("expected 0 nodes for failed target, got %d", len(data.Graph.Nodes))
	}
	if data.Meta.Collection == nil || data.Meta.Collection.State != ingest.OutcomeFailed {
		t.Fatalf("failed-empty target lost collection failure: %+v", data.Meta.Collection)
	}
}

func TestCollectorRetainsNonconformantV1CardObservation(t *testing.T) {
	body := []byte(`{"name":"Incomplete V1 Agent"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	data, err := NewA2ACollector().Collect(
		context.Background(),
		collector.CollectOptions{TargetURL: server.URL, ScanID: "nonconformant-v1"},
	)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if data.Meta.Collection == nil || data.Meta.Collection.State != ingest.OutcomeComplete {
		t.Fatalf("collection state = %+v", data.Meta.Collection)
	}
	var properties map[string]any
	for _, node := range data.Graph.Nodes {
		for _, kind := range node.Kinds {
			if kind == "A2AAgent" {
				properties = node.Properties
			}
		}
	}
	if properties == nil {
		t.Fatal("nonconformant card observation was dropped")
	}
	if properties["card_schema_version"] != "v1.0.1" ||
		properties["card_conformant"] != false {
		t.Fatalf("nonconformant properties = %+v", properties)
	}
	for _, edge := range data.Graph.Edges {
		switch edge.Kind {
		case "ADVERTISES_SKILL", "RUNS_ON", "AUTHENTICATES_WITH":
			t.Fatalf("nonconformant facts emitted functional edge: %+v", edge)
		}
	}
}

func TestCollector_MixedTargetOutcomesArePartial(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer okServer.Close()
	failedServer := httptest.NewServer(http.NotFoundHandler())
	defer failedServer.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURLs: []string{okServer.URL, failedServer.URL},
		ScanID:     "test-scan-partial",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if data.Meta.Collection == nil || data.Meta.Collection.State != ingest.OutcomePartial {
		t.Fatalf("mixed target report = %+v, want partial", data.Meta.Collection)
	}
	if len(data.Meta.Collection.Outcomes) != 2 {
		t.Fatalf("outcomes = %d, want 2", len(data.Meta.Collection.Outcomes))
	}
	if len(data.Meta.Collection.CoverageKeys) != 2 {
		t.Fatalf("coverage keys = %v, want one per target", data.Meta.Collection.CoverageKeys)
	}
	okScope := a2aCoverageKey(okServer.URL)
	failedScope := a2aCoverageKey(failedServer.URL)
	if okScope == failedScope {
		t.Fatal("distinct targets received the same coverage scope")
	}
	for _, node := range data.Graph.Nodes {
		if len(node.ObservationDomains) != 1 || node.ObservationDomains[0] != okScope {
			t.Fatalf("successful target fact domains = %v, want [%s]", node.ObservationDomains, okScope)
		}
	}
}

func TestCollector_EdgeProperties(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-props",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, e := range data.Graph.Edges {
		props := e.Properties
		if _, ok := props["scan_id"]; !ok {
			t.Errorf("edge %s missing scan_id", e.Kind)
		}
		if _, ok := props["last_seen"]; !ok {
			t.Errorf("edge %s missing last_seen", e.Kind)
		}
		if _, ok := props["confidence"]; !ok {
			t.Errorf("edge %s missing confidence", e.Kind)
		}
		if _, ok := props["risk_weight"]; !ok {
			t.Errorf("edge %s missing risk_weight", e.Kind)
		}
		if _, ok := props["is_composite"]; !ok {
			t.Errorf("edge %s missing is_composite", e.Kind)
		}

		if props["is_composite"] != false {
			t.Errorf("edge %s: expected is_composite=false, got %v", e.Kind, props["is_composite"])
		}
		if props["scan_id"] != "test-scan-props" {
			t.Errorf("edge %s: expected scan_id 'test-scan-props', got %v", e.Kind, props["scan_id"])
		}
	}
}

func TestCollector_NodeObjectID(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-objid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, n := range data.Graph.Nodes {
		objID, ok := n.Properties["objectid"].(string)
		if !ok || objID == "" {
			t.Errorf("node %s missing objectid", n.ID)
		}
		if objID != n.ID {
			t.Errorf("node objectid %q != node ID %q", objID, n.ID)
		}
	}
}

func TestCollector_SignedCard(t *testing.T) {
	body := loadFixture(t, "agent_card_signed.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-signed",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var agentNode *json.RawMessage
	for _, n := range data.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "A2AAgent" {
				raw, _ := json.Marshal(n.Properties)
				rm := json.RawMessage(raw)
				agentNode = &rm
			}
		}
	}
	if agentNode == nil {
		t.Fatal("expected A2AAgent node")
	}

	var props map[string]any
	if err := json.Unmarshal(*agentNode, &props); err != nil {
		t.Fatalf("unmarshal agent properties: %v", err)
	}

	if props["is_signed"] != true {
		t.Errorf("expected is_signed=true, got %v", props["is_signed"])
	}
	if _, legacy := props["signature_valid"]; legacy {
		t.Error("collector emitted legacy signature_valid alias")
	}
	if props["signature_verification_status"] != SigStatusUnsupportedVersion {
		t.Errorf("expected signature_verification_status=%s, got %v", SigStatusUnsupportedVersion, props["signature_verification_status"])
	}
	if props["auth_method"] != "mtls" {
		t.Errorf("expected auth_method=mtls, got %v", props["auth_method"])
	}
}

func TestCollector_SignedCard_ObjectForm_Valid(t *testing.T) {
	key := mustECDSAKey(t)
	card := signV1Card(t, validV10Card(), key, "trusted-key", "")
	body, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	trustedKeys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:   &key.PublicKey,
		KeyID: "trusted-key",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	trustedKeysPath := filepath.Join(t.TempDir(), "trusted.jwks")
	if err := os.WriteFile(trustedKeysPath, trustedKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector(WithTrustedKeysFile(trustedKeysPath))
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-signed-valid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var props map[string]any
	for _, n := range data.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "A2AAgent" {
				raw, _ := json.Marshal(n.Properties)
				_ = json.Unmarshal(raw, &props)
			}
		}
	}
	if props == nil {
		t.Fatal("expected A2AAgent node")
	}

	if props["is_signed"] != true {
		t.Errorf("expected is_signed=true, got %v", props["is_signed"])
	}
	if _, legacy := props["signature_valid"]; legacy {
		t.Error("collector emitted legacy signature_valid alias")
	}
	if props["signature_verification_status"] != SigStatusValidTrusted {
		t.Errorf("expected signature_verification_status=%s, got %v", SigStatusValidTrusted, props["signature_verification_status"])
	}
	if props["signature_key_source"] != SigKeySourceTrustedStore ||
		props["signature_key_trust"] != SigKeyTrustTrusted {
		t.Errorf("unexpected signature key provenance: source=%v trust=%v", props["signature_key_source"], props["signature_key_trust"])
	}
}

func TestCollector_DuplicateTargets(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL:  srv.URL,
		TargetURLs: []string{srv.URL},
		ScanID:     "test-scan-dedup",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var agentCount int
	for _, n := range data.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "A2AAgent" {
				agentCount++
			}
		}
	}
	if agentCount != 1 {
		t.Errorf("expected 1 A2AAgent node after dedup, got %d", agentCount)
	}
}

func TestCollector_OutputFormat(t *testing.T) {
	body := loadFixture(t, "agent_card_v030.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := NewA2ACollector()
	data, err := c.Collect(context.Background(), collector.CollectOptions{
		TargetURL: srv.URL,
		ScanID:    "test-scan-format",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Meta.Version != ingest.CurrentVersion {
		t.Errorf("expected meta version %d, got %d", ingest.CurrentVersion, data.Meta.Version)
	}
	if data.Meta.Type != "agenthound-ingest" {
		t.Errorf("expected meta type 'agenthound-ingest', got %q", data.Meta.Type)
	}
	if data.Meta.Collector != "a2a" {
		t.Errorf("expected meta collector 'a2a', got %q", data.Meta.Collector)
	}

	out, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(out, &roundTrip); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if _, ok := roundTrip["meta"]; !ok {
		t.Error("missing 'meta' in output")
	}
	if _, ok := roundTrip["graph"]; !ok {
		t.Error("missing 'graph' in output")
	}
}

package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	collector "github.com/adithyan-ak/agenthound/internal/collector"
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
	if props["signature_valid"] != false {
		t.Errorf("expected signature_valid=false (Phase 2 MVP), got %v", props["signature_valid"])
	}
	if props["auth_method"] != "mtls" {
		t.Errorf("expected auth_method=mtls, got %v", props["auth_method"])
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

	if data.Meta.Version != 1 {
		t.Errorf("expected meta version 1, got %d", data.Meta.Version)
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

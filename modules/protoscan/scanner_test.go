package protoscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const initializeOK = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"demo-mcp","version":"0.0.1"},"capabilities":{}}}`
const a2aCard = `{"name":"demo-agent","url":"http://demo-agent.example/api","description":"demo"}`

func mcpStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && (r.URL.Path == "/" || r.URL.Path == "/mcp") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(initializeOK))
			return
		}
		w.WriteHeader(404)
	}))
}

func a2aStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(a2aCard))
			return
		}
		w.WriteHeader(404)
	}))
}

func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse stub URL: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return p
}

func TestScan_DiscoversMCP(t *testing.T) {
	srv := mcpStub(t)
	defer srv.Close()

	s := &Scanner{
		Mode:     ModeMCP,
		MCPPorts: []int{portOf(t, srv)},
	}
	targets, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 MCP target, got %d", len(targets))
	}
	if got := targets[0].Meta["protocol"]; got != "mcp" {
		t.Errorf("protocol = %q, want mcp", got)
	}
}

func TestScan_DiscoversA2A(t *testing.T) {
	srv := a2aStub(t)
	defer srv.Close()

	s := &Scanner{
		Mode:     ModeA2A,
		A2APorts: []int{portOf(t, srv)},
	}
	targets, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 A2A target, got %d", len(targets))
	}
	if got := targets[0].Meta["protocol"]; got != "a2a" {
		t.Errorf("protocol = %q, want a2a", got)
	}
	if got := targets[0].Meta["agent_card_url"]; got == "" {
		t.Error("agent_card_url should be populated")
	}
}

func TestScan_DiscoversBoth(t *testing.T) {
	mcp := mcpStub(t)
	defer mcp.Close()
	a2a := a2aStub(t)
	defer a2a.Close()

	s := &Scanner{
		Mode:     ModeBoth,
		MCPPorts: []int{portOf(t, mcp)},
		A2APorts: []int{portOf(t, a2a)},
	}
	targets, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets (1 MCP + 1 A2A), got %d", len(targets))
	}
	var mcpFound, a2aFound bool
	for _, tgt := range targets {
		switch tgt.Meta["protocol"] {
		case "mcp":
			mcpFound = true
		case "a2a":
			a2aFound = true
		}
	}
	if !mcpFound || !a2aFound {
		t.Errorf("expected both protocols, got mcp=%v a2a=%v", mcpFound, a2aFound)
	}
}

func TestEmitDiscoveryNodes_MCP(t *testing.T) {
	srv := mcpStub(t)
	defer srv.Close()
	s := &Scanner{Mode: ModeMCP, MCPPorts: []int{portOf(t, srv)}}
	targets, _ := s.Scan(context.Background(), "127.0.0.1")
	g := EmitDiscoveryNodes(targets)
	if len(g.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(g.Nodes))
	}
	n := g.Nodes[0]
	if n.Kinds[0] != "MCPServer" {
		t.Errorf("kind = %q, want MCPServer", n.Kinds[0])
	}
	if got, _ := n.Properties["transport"].(string); got != "http" {
		t.Errorf("transport = %q, want http", got)
	}
	if got, _ := n.Properties["discovered_via"].(string); got != "protoscan" {
		t.Errorf("discovered_via = %q, want protoscan", got)
	}
}

func TestEmitDiscoveryNodes_A2AUsesBaseURLID(t *testing.T) {
	targets := []action.Target{{
		Kind:    "host",
		Address: "agent.example.com:443",
		Meta: map[string]string{
			"protocol":       "a2a",
			"url":            "https://agent.example.com",
			"agent_card_url": "https://agent.example.com/.well-known/agent-card.json",
		},
	}}
	g := EmitDiscoveryNodes(targets)
	if len(g.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(g.Nodes))
	}
	want := ingest.ComputeNodeID("A2AAgent", "https://agent.example.com")
	if g.Nodes[0].ID != want {
		t.Fatalf("A2A ID = %s, want %s", g.Nodes[0].ID, want)
	}
	if got, _ := g.Nodes[0].Properties["endpoint"].(string); got != "https://agent.example.com" {
		t.Errorf("endpoint = %q, want normalized base URL", got)
	}
}

func TestProbe_RejectsNonMCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer srv.Close()

	s := &Scanner{Mode: ModeMCP, MCPPorts: []int{portOf(t, srv)}}
	targets, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets (vLLM-shaped body), got %d", len(targets))
	}
}

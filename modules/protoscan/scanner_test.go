package protoscan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
	if n.Properties["auth_method"] != "unknown" || n.Properties["auth_assurance"] != "unknown" {
		t.Errorf("sparse discovery claimed auth absence: %+v", n.Properties)
	}
}

// mcpStubAtPath answers the JSON-RPC initialize ONLY at wantPath (404
// elsewhere), so a test can control which path protoscan matches. The shared
// mcpStub answers on both "/" and "/mcp", which would always match "/" first.
func mcpStubAtPath(t *testing.T, wantPath string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == wantPath {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(initializeOK))
			return
		}
		w.WriteHeader(404)
	}))
}

// TestEmitDiscoveryNodes_MCPMergesWithCollectorID is the Fix #1 regression: a
// protoscan-discovered MCP server MUST get the same deterministic node ID the
// mcp/config collectors compute via ingest.ComputeMCPServerID, so the nodes
// merge at the documented cross-collector merge point. Before the fix,
// EmitDiscoveryNodes hashed a path-less base URL via raw ComputeNodeID, so a
// server at /mcp never merged. Covers both the root ("/") and "/mcp" match
// cases — root must canonicalize to the path-less host:port form (trailing
// slash trimmed) that the collectors use for a bare URL.
func TestEmitDiscoveryNodes_MCPMergesWithCollectorID(t *testing.T) {
	t.Run("root path canonicalizes to path-less id", func(t *testing.T) {
		srv := mcpStubAtPath(t, "/")
		defer srv.Close()
		port := portOf(t, srv)
		s := &Scanner{Mode: ModeMCP, MCPPorts: []int{port}}
		targets, err := s.Scan(context.Background(), "127.0.0.1")
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		g := EmitDiscoveryNodes(targets)
		if len(g.Nodes) != 1 {
			t.Fatalf("got %d nodes, want 1", len(g.Nodes))
		}
		bareURL := fmt.Sprintf("http://127.0.0.1:%d", port)
		want := ingest.ComputeMCPServerID("http", bareURL)
		if g.Nodes[0].ID != want {
			t.Errorf("root MCP node ID = %s, want %s (must merge with a bare-URL config/mcp node)", g.Nodes[0].ID, want)
		}
		if ep, _ := g.Nodes[0].Properties["endpoint"].(string); ep != bareURL {
			t.Errorf("endpoint = %q, want path-less %q", ep, bareURL)
		}
	})

	t.Run("/mcp path preserved in id", func(t *testing.T) {
		srv := mcpStubAtPath(t, "/mcp")
		defer srv.Close()
		port := portOf(t, srv)
		s := &Scanner{Mode: ModeMCP, MCPPorts: []int{port}}
		targets, err := s.Scan(context.Background(), "127.0.0.1")
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		g := EmitDiscoveryNodes(targets)
		if len(g.Nodes) != 1 {
			t.Fatalf("got %d nodes, want 1", len(g.Nodes))
		}
		mcpURL := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
		want := ingest.ComputeMCPServerID("http", mcpURL)
		if g.Nodes[0].ID != want {
			t.Errorf("/mcp MCP node ID = %s, want %s (must merge with a /mcp config/mcp node)", g.Nodes[0].ID, want)
		}
	})
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
	if g.Nodes[0].Properties["auth_method"] != "unknown" ||
		g.Nodes[0].Properties["signature_verification_status"] != "unknown" {
		t.Errorf("sparse A2A discovery claimed assessed posture: %+v", g.Nodes[0].Properties)
	}
}

// TestScan_CancellationReturnsPartialAndError verifies that cancelling the
// context mid-scan surfaces context.Canceled (rather than swallowing it) while
// still returning the partial results gathered before cancellation. This
// mirrors networkscan.Scanner's contract; the discover CLI tolerates
// context.Canceled so the partial --output can still be written.
//
// Determinism mirrors networkscan.TestScanner_Cancellation: feed a port set
// large enough that the single-worker dispatch loop needs many iterations,
// slow each probe so cancellation has time to fire mid-dispatch, cancel via a
// timer, then assert the scanner observed cancellation (returns
// context.Canceled) and shut down cleanly. Cancellation legitimately
// interrupts in-flight probes, so the surviving partial count is best-effort;
// the contract under test is that the error is surfaced (not swallowed) and
// any returned target is well-formed.
func TestScan_CancellationReturnsPartialAndError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow every response so dispatch stays in flight when cancel fires.
		time.Sleep(30 * time.Millisecond)
		if r.Method == "POST" && (r.URL.Path == "/" || r.URL.Path == "/mcp") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(initializeOK))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	livePort := portOf(t, srv)

	// Many copies of the live port so each dispatched job hits the slow
	// server: dispatch needs dozens of iterations, giving cancel a window.
	ports := make([]int, 0, 200)
	for i := 0; i < 200; i++ {
		ports = append(ports, livePort)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	s := &Scanner{
		Mode:        ModeMCP,
		MCPPorts:    ports,
		Concurrency: 2,
		Timeout:     2 * time.Second,
	}

	results, err := s.Scan(ctx, "127.0.0.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// Partial results are best-effort under cancellation, but the return path
	// must deliver committed results (not drop them) and each must be valid.
	for _, tgt := range results {
		if tgt.Meta["protocol"] != "mcp" {
			t.Errorf("partial target protocol = %q, want mcp", tgt.Meta["protocol"])
		}
	}
}

// TestScan_ProgressReported verifies the optional Progress hook fires and the
// final sample reports every probe complete. ModeMCP with a single port over
// one host is exactly 1 job, so the terminal sample must be [1 1].
func TestScan_ProgressReported(t *testing.T) {
	srv := mcpStub(t)
	defer srv.Close()

	var mu sync.Mutex
	var calls [][2]int
	s := &Scanner{
		Mode:     ModeMCP,
		MCPPorts: []int{portOf(t, srv)},
		Progress: func(done, total int) {
			mu.Lock()
			calls = append(calls, [2]int{done, total})
			mu.Unlock()
		},
	}
	if _, err := s.Scan(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) == 0 {
		t.Fatal("Progress was never called")
	}
	last := calls[len(calls)-1]
	if last[0] != 1 || last[1] != 1 {
		t.Errorf("final progress = [%d %d], want [1 1]", last[0], last[1])
	}
}

// TestScan_ConcurrencyClamped is the A2 regression: an absurd Concurrency is
// clamped to MaxConcurrency, so the scan can't spawn a runaway goroutine /
// connection count. Completes normally and the receiver is clamped.
func TestScan_ConcurrencyClamped(t *testing.T) {
	srv := mcpStub(t)
	defer srv.Close()
	s := &Scanner{
		Mode:        ModeMCP,
		MCPPorts:    []int{portOf(t, srv)},
		Concurrency: 1 << 30,
		Timeout:     time.Second,
	}
	if _, err := s.Scan(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("Scan with huge Concurrency err = %v", err)
	}
	if s.Concurrency != MaxConcurrency {
		t.Errorf("Concurrency = %d, want clamped to %d", s.Concurrency, MaxConcurrency)
	}
}

// TestProbeMCP_RequiresDualAccept is part of the O1 fix: a Streamable-HTTP MCP
// server may 406 unless the client advertises both application/json AND
// text/event-stream. The probe must now send both and still match.
func TestProbeMCP_RequiresDualAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			w.WriteHeader(406)
			return
		}
		if r.Method == "POST" && (r.URL.Path == "/" || r.URL.Path == "/mcp") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(initializeOK))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	s := &Scanner{Mode: ModeMCP, MCPPorts: []int{portOf(t, srv)}}
	targets, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 MCP target (server requires dual Accept), got %d", len(targets))
	}
}

// TestProbeMCP_SSEFramedResponse is part of the O1 fix: a Streamable-HTTP MCP
// server may frame the initialize response as an SSE event (Content-Type:
// text/event-stream) rather than raw JSON. The probe must extract the data
// payload and still shape-match.
func TestProbeMCP_SSEFramedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && (r.URL.Path == "/" || r.URL.Path == "/mcp") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message\ndata: " + initializeOK + "\n\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	s := &Scanner{Mode: ModeMCP, MCPPorts: []int{portOf(t, srv)}}
	targets, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 MCP target from SSE-framed initialize, got %d", len(targets))
	}
}

// TestExtractSSEData covers the O1 SSE-payload extractor directly, including
// the non-SSE passthrough branch.
func TestExtractSSEData(t *testing.T) {
	if got := string(extractSSEData([]byte("event: message\ndata: {\"a\":1}\n\n"))); got != `{"a":1}` {
		t.Errorf("single data line = %q, want %q", got, `{"a":1}`)
	}
	if got := string(extractSSEData([]byte(`{"plain":true}`))); got != `{"plain":true}` {
		t.Errorf("non-SSE body should pass through unchanged, got %q", got)
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

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestMCPCollectorObservesRawTasksAndPreservesBoundedStreamableSessionState(t *testing.T) {
	const (
		protocolVersion = "2025-06-18"
		sessionID       = "agenthound-observer-session"
	)
	var (
		initializedSeen atomic.Bool
		standaloneSeen  atomic.Bool
		toolsSeen       atomic.Bool
		deleteSeen      atomic.Bool
		badHeaders      atomic.Bool
	)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodDelete {
			if r.Header.Get("MCP-Protocol-Version") != protocolVersion ||
				r.Header.Get("Mcp-Session-Id") != sessionID {
				badHeaders.Store(true)
				http.Error(w, "missing negotiated MCP headers", http.StatusBadRequest)
				return
			}
		}

		switch r.Method {
		case http.MethodGet:
			standaloneSeen.Store(true)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		case http.MethodDelete:
			deleteSeen.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodPost:
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Method != "initialize" &&
			(r.Header.Get("MCP-Protocol-Version") != protocolVersion ||
				r.Header.Get("Mcp-Session-Id") != sessionID) {
			badHeaders.Store(true)
			http.Error(w, "missing negotiated MCP headers", http.StatusBadRequest)
			return
		}

		switch request.Method {
		case "initialize":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", sessionID)
			writeRawSSEResult(t, w, request.ID, map[string]any{
				"protocolVersion": protocolVersion,
				"serverInfo":      map[string]any{"name": "raw-tasks-server", "version": "1.0.0"},
				"capabilities": map[string]any{
					"tools": map[string]any{},
					"tasks": map[string]any{
						"list":   map[string]any{},
						"cancel": map[string]any{},
						"requests": map[string]any{
							"tools": map[string]any{"call": map[string]any{}},
						},
					},
				},
			})
		case "notifications/initialized":
			initializedSeen.Store(true)
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			toolsSeen.Store(true)
			w.Header().Set("Content-Type", "application/json")
			writeRawResult(t, w, request.ID, map[string]any{"tools": []any{}})
		default:
			http.Error(w, "unexpected MCP method", http.StatusBadRequest)
		}
	}))
	defer httpServer.Close()

	data, err := NewMCPCollector().Collect(context.Background(), collector.CollectOptions{
		TargetURL: httpServer.URL,
		ScanID:    "raw-tasks-streamable",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	serverNode := nodeWithKind(t, data.Graph.Nodes, "MCPServer")
	if got := serverNode.Properties["has_tasks_capability"]; got != true {
		t.Fatalf("has_tasks_capability = %#v, want true", got)
	}
	capabilities, ok := serverNode.Properties["capabilities"].([]string)
	if !ok || !slices.Contains(capabilities, "tasks") {
		t.Fatalf("capabilities = %#v, want raw tasks capability", serverNode.Properties["capabilities"])
	}
	if badHeaders.Load() {
		t.Fatal("observer broke negotiated protocol-version or session headers")
	}
	if standaloneSeen.Load() {
		t.Fatal("collector opened the optional standalone SSE stream")
	}
	if !initializedSeen.Load() || !toolsSeen.Load() || !deleteSeen.Load() {
		t.Fatalf(
			"bounded streamable lifecycle incomplete: initialized=%t standalone=%t tools=%t delete=%t",
			initializedSeen.Load(), standaloneSeen.Load(), toolsSeen.Load(), deleteSeen.Load(),
		)
	}
}

func TestInitializeTasksPresenceSemantics(t *testing.T) {
	tests := []struct {
		name       string
		result     string
		wantValue  any
		wantExists bool
		wantTasks  bool
	}{
		{name: "non-null object", result: `{"capabilities":{"tasks":{}}}`, wantValue: true, wantExists: true, wantTasks: true},
		{name: "absent key", result: `{"capabilities":{"tools":{}}}`, wantValue: false, wantExists: true},
		{name: "explicit null", result: `{"capabilities":{"tasks":null}}`},
		{name: "non-object value", result: `{"capabilities":{"tasks":[]}}`},
		{name: "capabilities absent", result: `{}`},
		{name: "capabilities null", result: `{"capabilities":null}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &initializeWireObserver{}
			if !observer.observeResult(json.RawMessage(test.result)) {
				t.Fatal("valid initialize result was not observed")
			}
			node := ingest.Node{Properties: map[string]any{"capabilities": []string{"tools"}}}
			applyInitializeWireObservation(&node, observer)

			got, exists := node.Properties["has_tasks_capability"]
			if exists != test.wantExists || (exists && got != test.wantValue) {
				t.Fatalf("has_tasks_capability = (%#v, %t), want (%#v, %t)", got, exists, test.wantValue, test.wantExists)
			}
			capabilities, ok := node.Properties["capabilities"].([]string)
			if !ok {
				t.Fatalf("capabilities = %#v, want []string", node.Properties["capabilities"])
			}
			if slices.Contains(capabilities, "tasks") != test.wantTasks {
				t.Fatalf("capabilities = %v, want tasks=%t", capabilities, test.wantTasks)
			}
		})
	}
}

func TestInitializeObserverCapturesLegacySSE(t *testing.T) {
	events := make(chan []byte, 4)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("test server does not support flushing")
				return
			}
			_, _ = fmt.Fprint(w, "event: endpoint\ndata: /messages\n\n")
			flusher.Flush()
			for {
				select {
				case event := <-events:
					_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", event)
					flusher.Flush()
				case <-r.Context().Done():
					return
				}
			}
		case r.Method == http.MethodPost && r.URL.Path == "/messages":
			var request struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if request.Method == "initialize" {
				response, err := json.Marshal(map[string]any{
					"jsonrpc": "2.0",
					"id":      request.ID,
					"result": map[string]any{
						"protocolVersion": "2025-06-18",
						"serverInfo":      map[string]any{"name": "legacy-sse", "version": "1.0.0"},
						"capabilities":    map[string]any{"tasks": map[string]any{}},
					},
				})
				if err != nil {
					t.Errorf("marshal SSE response: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				events <- response
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer httpServer.Close()

	transport, observer := withInitializeWireObserver(&mcpsdk.SSEClientTransport{Endpoint: httpServer.URL + "/sse"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "observer-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect legacy SSE: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close legacy SSE: %v", err)
	}
	if got := observer.tasksState(); got != tasksCapabilityPresent {
		t.Fatalf("legacy SSE tasks state = %v, want present", got)
	}
}

func TestInitializeObserverCapturesStdio(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestInitializeObserverStdioHelperProcess$")
	command.Env = append(os.Environ(), "AGENTHOUND_MCP_STDIO_HELPER=1")
	transport, observer := withInitializeWireObserver(&mcpsdk.CommandTransport{
		Command:           command,
		TerminateDuration: 5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "observer-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect stdio: %v", err)
	}
	if got := observer.tasksState(); got != tasksCapabilityPresent {
		t.Fatalf("stdio tasks state = %v, want present", got)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close stdio: %v", err)
	}
}

func TestInitializeObserverStdioHelperProcess(t *testing.T) {
	if os.Getenv("AGENTHOUND_MCP_STDIO_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(2)
		}
		if request.Method != "initialize" {
			continue
		}
		if err := encoder.Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      request.ID,
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "stdio-observer", "version": "1.0.0"},
				"capabilities":    map[string]any{"tasks": map[string]any{}},
			},
		}); err != nil {
			os.Exit(2)
		}
	}
	os.Exit(0)
}

func writeRawResult(t *testing.T, w http.ResponseWriter, id json.RawMessage, result any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}); err != nil {
		t.Errorf("encode JSON-RPC response: %v", err)
	}
}

func writeRawSSEResult(t *testing.T, w http.ResponseWriter, id json.RawMessage, result any) {
	t.Helper()
	response, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
	if err != nil {
		t.Errorf("encode JSON-RPC SSE response: %v", err)
		return
	}
	if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", response); err != nil {
		t.Errorf("write JSON-RPC SSE response: %v", err)
	}
}

func nodeWithKind(t *testing.T, nodes []ingest.Node, kind string) ingest.Node {
	t.Helper()
	for _, node := range nodes {
		if slices.Contains(node.Kinds, kind) {
			return node
		}
	}
	t.Fatalf("node kind %q not found", kind)
	return ingest.Node{}
}

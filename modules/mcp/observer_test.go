package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
)

func TestToolObserverInitializesAndExhaustsPagination(t *testing.T) {
	const (
		token      = "mcp-observer-secret"
		targetName = "z-last-tool"
		targetDesc = "Observed only after pagination."
	)
	previousVersion := common.CollectorVersion()
	common.SetCollectorVersion("1.2.3-test")
	t.Cleanup(func() { common.SetCollectorVersion(previousVersion) })

	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "observer-test", Version: "1.0.0"},
		&mcpsdk.ServerOptions{PageSize: 1},
	)
	addObserverTestTool(server, "a-first-tool", "First page.")
	addObserverTestTool(server, "m-middle-tool", "Second page.")
	addObserverTestTool(server, targetName, targetDesc)

	handler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	var listCalls atomic.Int32
	var initializeVersionSeen atomic.Bool
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte(`"method":"tools/list"`)) {
			listCalls.Add(1)
		}
		if bytes.Contains(body, []byte(`"method":"initialize"`)) &&
			bytes.Contains(body, []byte(`"version":"1.2.3-test"`)) {
			initializeVersionSeen.Store(true)
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	observed, err := (ToolObserver{}).Observe(
		context.Background(),
		ServerSpec{
			Name:      "observer-test",
			Transport: "http",
			URL:       httpServer.URL,
			Headers:   map[string]string{"Authorization": "Bearer " + token},
		},
		targetName,
	)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observed.Name != targetName || observed.Description != targetDesc {
		t.Fatalf("observation = %+v", observed)
	}
	if got := listCalls.Load(); got != 3 {
		t.Fatalf("tools/list calls = %d, want 3 paginated requests", got)
	}
	if !initializeVersionSeen.Load() {
		t.Fatal("initialize did not advertise the injected AgentHound version")
	}
}

func TestToolObserverRejectsRedirects(t *testing.T) {
	destinationCalls := atomic.Int32{}
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls.Add(1)
	}))
	defer destination.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer redirect.Close()

	_, err := (ToolObserver{RejectRedirects: true}).Observe(
		context.Background(),
		ServerSpec{Name: "redirect", Transport: "http", URL: redirect.URL},
		"tool",
	)
	if err == nil || !strings.Contains(err.Error(), "initialize failed") {
		t.Fatalf("Observe error = %v, want categorized initialize failure", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "redirect") {
		t.Fatalf("Observe error exposed raw redirect detail: %v", err)
	}
	if got := destinationCalls.Load(); got != 0 {
		t.Fatalf("redirect destination calls = %d, want zero", got)
	}
}

func TestToolObserverOmitsRawTransportSetupError(t *testing.T) {
	const sentinel = "TRANSPORT-SETUP-SECRET-7b2f"

	_, err := (ToolObserver{}).Observe(
		context.Background(),
		ServerSpec{Name: "unsupported", Transport: sentinel},
		"tool",
	)
	if err == nil || !strings.Contains(err.Error(), "transport setup failed") {
		t.Fatalf("Observe error = %v, want categorized transport setup failure", err)
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("Observe error exposed raw transport detail: %v", err)
	}
}

func TestToolObserverOmitsRawInitializeError(t *testing.T) {
	const sentinel = "INITIALIZE-SECRET-941a"
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeObserverRPCError(w, r, sentinel)
	}))
	defer httpServer.Close()

	_, err := (ToolObserver{}).Observe(
		context.Background(),
		ServerSpec{Name: "initialize-error", Transport: "http", URL: httpServer.URL},
		"tool",
	)
	if err == nil || !strings.Contains(err.Error(), "initialize failed") {
		t.Fatalf("Observe error = %v, want categorized initialize failure", err)
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("Observe error exposed raw initialize detail: %v", err)
	}
}

func TestToolObserverOmitsRawToolsListError(t *testing.T) {
	const sentinel = "TOOLS-LIST-SECRET-5cd1"
	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "list-error", Version: "1.0.0"}, nil,
	)
	addObserverTestTool(server, "tool", "description")
	handler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "request read failed", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte(`"method":"tools/list"`)) {
			writeObserverRPCErrorBody(w, body, sentinel)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	_, err := (ToolObserver{}).Observe(
		context.Background(),
		ServerSpec{Name: "list-error", Transport: "http", URL: httpServer.URL},
		"tool",
	)
	if err == nil || !strings.Contains(err.Error(), "tools/list failed") {
		t.Fatalf("Observe error = %v, want categorized tools/list failure", err)
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("Observe error exposed raw tools/list detail: %v", err)
	}
}

func TestSafeToolObserverErrorPreservesOnlyContextSentinel(t *testing.T) {
	const sentinel = "WRAPPED-CONTEXT-SECRET-04ee"

	for _, contextErr := range []error{context.DeadlineExceeded, context.Canceled} {
		rawErr := fmt.Errorf("%s: %w", sentinel, contextErr)
		err := safeToolObserverError("initialize", rawErr)
		if !errors.Is(err, contextErr) {
			t.Fatalf("errors.Is(%v, %v) = false", err, contextErr)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("sanitized context error exposed raw detail: %v", err)
		}
	}
}

func TestToolObserverRequiresToolsCapability(t *testing.T) {
	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "no-tools", Version: "1.0.0"},
		&mcpsdk.ServerOptions{Capabilities: &mcpsdk.ServerCapabilities{}},
	)
	handler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()

	_, err := (ToolObserver{}).Observe(
		context.Background(),
		ServerSpec{Name: "no-tools", Transport: "http", URL: httpServer.URL},
		"missing",
	)
	if err == nil {
		t.Fatal("Observe succeeded without an initialized tools capability")
	}
}

func TestToolObserverRejectsDuplicateTargetAcrossPaginatedResponses(t *testing.T) {
	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "duplicate-test", Version: "1.0.0"},
		&mcpsdk.ServerOptions{PageSize: 1},
	)
	addObserverTestTool(server, "first-source-name", "first")
	addObserverTestTool(server, "second-source-name", "second")
	handler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	var listCalls atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		responseBody := recorder.Body.Bytes()
		if bytes.Contains(body, []byte(`"method":"tools/list"`)) {
			listCalls.Add(1)
			responseBody = bytes.ReplaceAll(responseBody, []byte(`"name":"first-source-name"`), []byte(`"name":"duplicate-tool"`))
			responseBody = bytes.ReplaceAll(responseBody, []byte(`"name":"second-source-name"`), []byte(`"name":"duplicate-tool"`))
		}
		for name, values := range recorder.Header() {
			w.Header()[name] = append([]string(nil), values...)
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(responseBody)
	}))
	defer httpServer.Close()

	_, err := (ToolObserver{}).Observe(context.Background(), ServerSpec{
		Name: "duplicate-test", Transport: "http", URL: httpServer.URL,
	}, "duplicate-tool")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "not unique") {
		t.Fatalf("Observe error = %v, want duplicate rejection", err)
	}
	if got := listCalls.Load(); got != 2 {
		t.Fatalf("tools/list calls = %d, want both pages observed", got)
	}
}

func TestToolObserverBoundsHangingSessionDelete(t *testing.T) {
	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "close-test", Version: "1.0.0"}, nil,
	)
	addObserverTestTool(server, "tool", "description")
	handler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	deleteCanceled := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			<-r.Context().Done()
			close(deleteCanceled)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte(`"method":"tools/list"`)) {
			time.Sleep(400 * time.Millisecond)
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	started := time.Now()
	observed, err := (ToolObserver{InitTimeout: 500 * time.Millisecond}).Observe(
		context.Background(),
		ServerSpec{Name: "close-test", Transport: "http", URL: httpServer.URL},
		"tool",
	)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observed.Name != "tool" {
		t.Fatalf("observation = %+v", observed)
	}
	if elapsed := time.Since(started); elapsed > 700*time.Millisecond {
		t.Fatalf("Observe took %v while session DELETE hung", elapsed)
	}
	select {
	case <-deleteCanceled:
	case <-time.After(time.Second):
		t.Fatal("hanging session DELETE was not canceled by the observer HTTP bound")
	}
}

func TestToolObserverCountsSDKRequestsAgainstCampaignBudget(t *testing.T) {
	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "budget-test", Version: "1.0.0"}, nil,
	)
	addObserverTestTool(server, "tool", "description")
	httpServer := httptest.NewServer(mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	))
	defer httpServer.Close()

	ctx, cancel, budget := campaign.NewBudgetContext(context.Background(), campaign.RunLimits{
		RequestLimit: 16, MutationLimit: 1, ElapsedLimit: time.Second,
	})
	defer cancel()
	_, err := (ToolObserver{}).Observe(ctx, ServerSpec{
		Name: "budget-test", Transport: "http", URL: httpServer.URL,
	}, "tool")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if got := budget.Snapshot().RequestsUsed; got < 2 {
		t.Fatalf("requests used = %d, want initialized MCP lifecycle requests", got)
	}
}

func addObserverTestTool(server *mcpsdk.Server, name, description string) {
	server.AddTool(
		&mcpsdk.Tool{
			Name:        name,
			Description: description,
			InputSchema: &jsonschema.Schema{Type: "object"},
		},
		func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
			return &mcpsdk.CallToolResult{}, nil
		},
	)
}

func writeObserverRPCError(w http.ResponseWriter, r *http.Request, message string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request read failed", http.StatusInternalServerError)
		return
	}
	writeObserverRPCErrorBody(w, body, message)
}

func writeObserverRPCErrorBody(w http.ResponseWriter, body []byte, message string) {
	var request struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		http.Error(w, "request decode failed", http.StatusBadRequest)
		return
	}
	response, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      request.ID,
		"error": map[string]any{
			"code":    -32000,
			"message": message,
		},
	})
	if err != nil {
		http.Error(w, "response encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(response)
}

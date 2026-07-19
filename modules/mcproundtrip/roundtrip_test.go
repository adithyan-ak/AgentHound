package mcproundtrip

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

type roundtripContextForgeFixture struct {
	mu                  sync.Mutex
	description         string
	version             int64
	modifiedUserAgent   string
	writes              int
	intermediateMCPRead bool
	mcp                 *mcpsdk.Server
	mcpHTTP             *httptest.Server
	managementHTTP      *httptest.Server
}

func newRoundtripContextForgeFixture(t *testing.T) *roundtripContextForgeFixture {
	return newRoundtripContextForgeFixtureWithTLS(t, false)
}

func newRoundtripContextForgeFixtureWithTLS(t *testing.T, useTLS bool) *roundtripContextForgeFixture {
	t.Helper()
	f := &roundtripContextForgeFixture{description: origDesc, version: 1}
	f.mcp = mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "contextforge-roundtrip-test", Version: "1.0.5"}, nil,
	)
	f.publishTool(origDesc)
	sdkHandler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return f.mcp },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read MCP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if strings.Contains(string(body), `"method":"tools/list"`) {
			f.mu.Lock()
			if f.writes == 1 && f.description != origDesc {
				f.intermediateMCPRead = true
			}
			f.mu.Unlock()
		}
		sdkHandler.ServeHTTP(w, r)
	})
	if useTLS {
		f.mcpHTTP = httptest.NewTLSServer(mcpHandler)
		f.managementHTTP = httptest.NewTLSServer(http.HandlerFunc(f.serveManagement))
	} else {
		f.mcpHTTP = httptest.NewServer(mcpHandler)
		f.managementHTTP = httptest.NewServer(http.HandlerFunc(f.serveManagement))
	}
	t.Cleanup(func() {
		f.managementHTTP.Close()
		f.mcpHTTP.Close()
	})
	return f
}

func TestRealContextForgeRoundtripInsecureAppliesToBothSurfacesAndReceiptObservations(t *testing.T) {
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())
	t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", roundtripManagementToken())
	t.Setenv("AGENTHOUND_MCP_TOKEN", "")
	fixture := newRoundtripContextForgeFixtureWithTLS(t, true)

	res, err := (&Scenario{}).Run(context.Background(), campaign.RunInput{
		Host:         fixture.mcpHTTP.URL + "/servers/" + testServerUUID + "/mcp",
		EngagementID: "ENG-INSECURE-REAL", Commit: true, Insecure: true,
		Params: map[string]string{
			"target-id": testTargetID, "adapter": action.ContextForgeProfile,
			"management-url": fixture.managementHTTP.URL,
		},
	})
	if err != nil {
		t.Fatalf("Run with explicit insecure: %v", err)
	}
	if !res.Report.TargetClean() {
		t.Fatalf("roundtrip report = %+v", res.Report)
	}
}

func (f *roundtripContextForgeFixture) publishTool(description string) {
	f.mcp.AddTool(&mcpsdk.Tool{
		Name: testTargetID, Description: description,
		InputSchema: &jsonschema.Schema{Type: "object"},
	}, func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		return &mcpsdk.CallToolResult{}, nil
	})
}

func (f *roundtripContextForgeFixture) serveManagement(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+roundtripManagementToken() {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/email/me":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"email": "operator@example.com", "is_admin": false, "is_active": true,
		})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/rbac/my/permissions":
		_ = json.NewEncoder(w).Encode([]string{"servers.read", "tools.read", "tools.update"})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/servers/"+testServerUUID:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": testServerUUID, "ownerEmail": "operator@example.com",
			"associatedToolIds": []string{testToolUUID},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/servers/"+testServerUUID+"/tools":
		_ = json.NewEncoder(w).Encode([]map[string]any{f.toolRecord()})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/tools/"+testToolUUID:
		_ = json.NewEncoder(w).Encode(f.toolRecord())
	case r.Method == http.MethodPut && r.URL.Path == "/v1/tools/"+testToolUUID:
		var body struct {
			Description string `json:"description"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.description = body.Description
		f.version++
		f.modifiedUserAgent = r.UserAgent()
		f.writes++
		f.mu.Unlock()
		f.publishTool(body.Description)
		_ = json.NewEncoder(w).Encode(f.toolRecord())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *roundtripContextForgeFixture) toolRecord() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]any{
		"id": testToolUUID, "name": testTargetID, "description": f.description,
		"version": f.version, "modifiedUserAgent": f.modifiedUserAgent,
		"ownerEmail": "operator@example.com",
	}
}

func roundtripManagementToken() string {
	encode := func(value any) string {
		data, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(map[string]string{"alg": "none"}) + "." + encode(map[string]any{
		"sub": "operator@example.com", "token_use": "api",
		"user":   map[string]any{"email": "operator@example.com", "is_admin": false},
		"scopes": map[string]any{"permissions": []string{"*"}},
	}) + ".signature"
}

func TestRealContextForgePreflightFailureNeedsNoCleanup(t *testing.T) {
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())
	t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", "not-the-accepted-token")
	t.Setenv("AGENTHOUND_MCP_TOKEN", "")
	fixture := newRoundtripContextForgeFixture(t)

	res, err := (&Scenario{}).Run(context.Background(), campaign.RunInput{
		Host:         fixture.mcpHTTP.URL + "/servers/" + testServerUUID + "/mcp",
		EngagementID: "ENG-PREFLIGHT-FAIL", Commit: true,
		Params: map[string]string{
			"target-id": testTargetID, "adapter": action.ContextForgeProfile,
			"management-url": fixture.managementHTTP.URL,
		},
	})
	if !errors.Is(err, campaign.ErrMutationFailed) {
		t.Fatalf("Run error = %v, want mutation failed", err)
	}
	if res.Report.Cleanup.Status != campaign.CleanupNotApplicable ||
		res.Report.Cleanup.Postcondition != "mutation_not_applied" {
		t.Fatalf("cleanup = %+v, want not applicable", res.Report.Cleanup)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.writes != 0 {
		t.Fatalf("preflight failure issued %d writes", fixture.writes)
	}
}

func TestRealContextForgeRoundtripProvesIntermediateChangeAndRestoration(t *testing.T) {
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())
	t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", roundtripManagementToken())
	t.Setenv("AGENTHOUND_MCP_TOKEN", "")
	fixture := newRoundtripContextForgeFixture(t)

	res, err := (&Scenario{}).Run(context.Background(), campaign.RunInput{
		Host:         fixture.mcpHTTP.URL + "/servers/" + testServerUUID + "/mcp",
		EngagementID: "ENG-REAL", Commit: true,
		Params: map[string]string{
			"target-id": testTargetID, "adapter": action.ContextForgeProfile,
			"management-url": fixture.managementHTTP.URL,
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Report.Oracle.Outcome != string(campaign.OracleMutationVerified) ||
		res.Report.Cleanup.Status != campaign.CleanupRestored || !res.Report.TargetClean() {
		t.Fatalf("roundtrip report = %+v", res.Report)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if !fixture.intermediateMCPRead {
		t.Fatal("roundtrip did not prove an intermediate MCP-visible change")
	}
	if fixture.writes != 2 {
		t.Fatalf("management writes = %d, want exactly one forward and one restore", fixture.writes)
	}
	if fixture.description != origDesc {
		t.Fatalf("description = %q, want original", fixture.description)
	}
}

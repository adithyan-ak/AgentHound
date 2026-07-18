package mcppoison

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

const (
	testToolName = "support-lookup"
	testToolID   = "22222222222242228222222222222222"
	testServerID = "11111111111141118111111111111111"
	testTeamID   = "33333333333343338333333333333333"
	testOriginal = "Read support tickets."
	testUpdated  = "Round-trip mutation."
	testOwner    = "operator@example.com"
)

type contextForgeFixture struct {
	t                    *testing.T
	mu                   sync.Mutex
	record               contextForgeTool
	writes               int
	putAttempts          int
	rejectPutAttempt     int
	rejectPutStatus      int
	normalize            func(string) string
	dropWriteBody        bool
	writeStatus          int
	writeResponse        func(int, contextForgeTool) contextForgeTool
	skipMCPUpdateAttempt int
	associationBody      string
	contentType          string
	serverResponseID     string
	profileEmail         string
	profileAdmin         bool
	profileActive        bool
	profileStatus        int
	effectivePermissions []string
	permissionTeamIDs    []string
	expectedMCPAuth      string
	mcpAuthSeen          bool
	toolReads            int
	toolResponsePadding  int
	onToolRead           func(int)
	onWrite              func()
	mcpServer            *mcpsdk.Server
	mcpHTTP              *httptest.Server
	managementHTTP       *httptest.Server
}

func newContextForgeFixture(t *testing.T) *contextForgeFixture {
	return newContextForgeFixtureWithTLS(t, false)
}

func newContextForgeFixtureWithTLS(t *testing.T, useTLS bool) *contextForgeFixture {
	t.Helper()
	f := &contextForgeFixture{
		t: t,
		record: contextForgeTool{
			ID: testToolID, Name: testToolName, Description: testOriginal,
			Version: 1, OwnerEmail: testOwner, TeamID: testTeamID,
		},
		contentType:          "application/json; charset=utf-8",
		serverResponseID:     testServerID,
		profileEmail:         testOwner,
		profileActive:        true,
		effectivePermissions: []string{"servers.read", "tools.read", "tools.update"},
	}
	f.mcpServer = mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "contextforge-test", Version: "1.0.5"}, nil,
	)
	f.setMCPDescription(testOriginal)
	mcpHandler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return f.mcpServer },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)
	mcpHTTPHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		expected := f.expectedMCPAuth
		if expected != "" && r.Header.Get("Authorization") == expected {
			f.mcpAuthSeen = true
		}
		f.mu.Unlock()
		if expected != "" && r.Header.Get("Authorization") != expected {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mcpHandler.ServeHTTP(w, r)
	})
	managementHandler := http.HandlerFunc(f.serveManagement)
	if useTLS {
		f.mcpHTTP = httptest.NewTLSServer(mcpHTTPHandler)
		f.managementHTTP = httptest.NewTLSServer(managementHandler)
	} else {
		f.mcpHTTP = httptest.NewServer(mcpHTTPHandler)
		f.managementHTTP = httptest.NewServer(managementHandler)
	}
	t.Cleanup(func() {
		f.managementHTTP.Close()
		f.mcpHTTP.Close()
	})
	return f
}

func (f *contextForgeFixture) setMCPDescription(description string) {
	f.mcpServer.AddTool(
		&mcpsdk.Tool{
			Name: testToolName, Description: description,
			InputSchema: &jsonschema.Schema{Type: "object"},
		},
		func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
			return &mcpsdk.CallToolResult{}, nil
		},
	)
}

func (f *contextForgeFixture) serveManagement(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+os.Getenv("AGENTHOUND_CONTEXTFORGE_TOKEN") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", f.contentType)
	switch {
	case r.Method == http.MethodGet && r.URL.EscapedPath() == identityReadPath():
		if f.profileStatus != 0 {
			w.WriteHeader(f.profileStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"email": f.profileEmail, "is_admin": f.profileAdmin, "is_active": f.profileActive,
		})
	case r.Method == http.MethodGet && r.URL.EscapedPath() == permissionsReadPath(""):
		f.mu.Lock()
		f.permissionTeamIDs = append(f.permissionTeamIDs, r.URL.Query().Get("team_id"))
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.effectivePermissions)
	case r.Method == http.MethodGet && r.URL.EscapedPath() == "/v1/servers/"+testServerID:
		_ = json.NewEncoder(w).Encode(contextForgeServer{
			ID: f.serverResponseID, TeamID: testTeamID, OwnerEmail: testOwner,
			AssociatedToolIDs: []string{testToolID},
		})
	case r.Method == http.MethodGet && r.URL.EscapedPath() == "/v1/servers/"+testServerID+"/tools":
		if f.associationBody != "" {
			_, _ = w.Write([]byte(f.associationBody))
			return
		}
		f.mu.Lock()
		record := f.record
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode([]contextForgeTool{record})
	case r.Method == http.MethodGet && r.URL.EscapedPath() == "/v1/tools/"+testToolID:
		f.mu.Lock()
		f.toolReads++
		readNumber := f.toolReads
		onToolRead := f.onToolRead
		f.mu.Unlock()
		if onToolRead != nil {
			onToolRead(readNumber)
		}
		f.mu.Lock()
		record := f.record
		padding := f.toolResponsePadding
		f.mu.Unlock()
		if padding > 0 {
			data, err := json.Marshal(record)
			if err != nil {
				f.t.Fatal(err)
			}
			var response map[string]any
			if err := json.Unmarshal(data, &response); err != nil {
				f.t.Fatal(err)
			}
			response["inputSchema"] = strings.Repeat("x", padding)
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		_ = json.NewEncoder(w).Encode(record)
	case r.Method == http.MethodPut && r.URL.EscapedPath() == "/v1/tools/"+testToolID:
		f.mu.Lock()
		f.putAttempts++
		putAttempt := f.putAttempts
		rejectPutAttempt := f.rejectPutAttempt
		f.mu.Unlock()
		if rejectPutAttempt == putAttempt {
			status := f.rejectPutStatus
			if status == 0 {
				status = http.StatusServiceUnavailable
			}
			w.WriteHeader(status)
			return
		}
		var body struct {
			Description string `json:"description"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if f.onWrite != nil {
			f.onWrite()
		}
		if f.normalize != nil {
			body.Description = f.normalize(body.Description)
		}
		f.mu.Lock()
		f.record.Description = body.Description
		f.record.Version++
		f.record.ModifiedUserAgent = r.UserAgent()
		f.writes++
		record := f.record
		skipMCPUpdateAttempt := f.skipMCPUpdateAttempt
		f.mu.Unlock()
		if putAttempt != skipMCPUpdateAttempt {
			f.setMCPDescription(body.Description)
		}
		if f.writeStatus != 0 {
			w.WriteHeader(f.writeStatus)
			return
		}
		if f.dropWriteBody {
			return
		}
		if f.writeResponse != nil {
			record = f.writeResponse(putAttempt, record)
		}
		_ = json.NewEncoder(w).Encode(record)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *contextForgeFixture) target() action.Target {
	return action.Target{Kind: "url", Address: f.mcpHTTP.URL + "/servers/" + testServerID + "/mcp"}
}

func (f *contextForgeFixture) payload(engagement string, dryRun bool) action.PoisonPayload {
	return action.PoisonPayload{
		TargetID: testToolName, InjectionContent: testUpdated, Mode: "replace",
		EngagementID: engagement, DryRun: dryRun,
		Extras: map[string]any{
			"adapter": action.ContextForgeProfile, "management-url": f.managementHTTP.URL,
		},
	}
}

func (f *contextForgeFixture) snapshot() (contextForgeTool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.record, f.writes
}

func testJWT(t *testing.T, permissions []string, email string, admin bool, teams ...string) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(map[string]string{"alg": "none"}) + "." + encode(map[string]any{
		"scopes": map[string]any{"permissions": permissions},
		"sub":    email, "token_use": "api", "teams": teams,
		"user": map[string]any{"email": email, "is_admin": admin},
	}) + ".signature"
}

func testSessionJWT(t *testing.T, permissions []string) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(map[string]string{"alg": "none"}) + "." + encode(map[string]any{
		"sub": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "token_use": "session",
		"scopes": map[string]any{"permissions": permissions},
	}) + ".signature"
}

func newTestPoisoner(t *testing.T) *Poisoner {
	t.Helper()
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())
	t.Setenv("AGENTHOUND_MCP_TOKEN", "")
	p := New()
	p.pollInterval = 0
	p.pollAttempts = 3
	return p
}

func authorizeFixture(t *testing.T) {
	t.Helper()
	t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", testSessionJWT(t, nil))
}

func TestContextForgePoisonPersistsTypedReceiptBeforeWriteAndReverts(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	engagement := "ENG-CONTEXTFORGE"
	receiptPath := filepath.Join(p.Stateful().StateDir(), engagement+".json")
	fixture.onWrite = func() {
		if _, err := os.Stat(receiptPath); err != nil {
			t.Errorf("receipt was not persisted before management write: %v", err)
		}
	}

	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload(engagement, false))
	if err != nil {
		t.Fatalf("Poison: %v", err)
	}
	if receipt.ContextForge == nil {
		t.Fatal("receipt has no typed ContextForge state")
	}
	state := receipt.ContextForge
	if state.ReceiptType != action.ContextForgeReceiptType ||
		state.ReceiptVersion != action.ContextForgeReceiptVersion ||
		state.ContractID != action.ContextForgeContractID {
		t.Fatalf("typed receipt identity = %+v", state)
	}
	if state.Management.ToolID != testToolID || state.Management.ServerID != testServerID ||
		state.Management.OriginalVersion != 1 || state.Management.ForwardUserAgent == "" ||
		state.Management.IdentityReadPath != identityReadPath() ||
		state.Management.ServerTeamID != testTeamID || state.Management.ToolTeamID != testTeamID ||
		state.Management.ServerPermissionsReadPath != permissionsReadPath(testTeamID) ||
		state.Management.ToolPermissionsReadPath != permissionsReadPath(testTeamID) ||
		state.Management.RestoreUserAgent == "" ||
		!validOpaqueOperationID(state.Management.ForwardOperationID) ||
		!validOpaqueOperationID(state.Management.RestoreOperationID) ||
		state.Management.ForwardOperationID == state.Management.RestoreOperationID {
		t.Fatalf("typed management state = %+v", state.Management)
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != testUpdated || record.Version != 2 ||
		record.ModifiedUserAgent != state.Management.ForwardUserAgent {
		t.Fatalf("post-poison state = %+v, writes=%d", record, writes)
	}
	persisted, err := p.Stateful().ReadReceipts(engagement)
	if err != nil || len(persisted) != 1 {
		t.Fatalf("persisted receipts = %d, %v", len(persisted), err)
	}
	encoded, _ := json.Marshal(persisted)
	if strings.Contains(string(encoded), os.Getenv("AGENTHOUND_CONTEXTFORGE_TOKEN")) {
		t.Fatal("management credential persisted in receipt")
	}

	if err := p.Revert(context.Background(), receipt); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	record, writes = fixture.snapshot()
	if writes != 2 || record.Description != testOriginal || record.Version != 3 ||
		record.ModifiedUserAgent != state.Management.RestoreUserAgent {
		t.Fatalf("post-revert state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeCanonicalizesToolNameInDurableReceipt(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	payload := fixture.payload("ENG-CANONICAL-NAME", false)
	payload.TargetID = "  " + testToolName + "  "
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if err != nil {
		t.Fatalf("Poison: %v", err)
	}
	if receipt.TargetID != testToolName {
		t.Fatalf("receipt target id = %q, want %q", receipt.TargetID, testToolName)
	}
	if err := validateContextForgeReceipt(receipt); err != nil {
		t.Fatalf("persisted receipt rejected itself: %v", err)
	}
	if err := p.Revert(context.Background(), receipt); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	record, writes := fixture.snapshot()
	if writes != 2 || record.Description != testOriginal {
		t.Fatalf("roundtrip state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRejectsOversizedOutboundBeforeReceiptOrWrite(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	payload := fixture.payload("ENG-REQUEST-BOUND", false)
	payload.InjectionContent = strings.Repeat("x", int(contextForgeMaxRequestBytes))
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if receipt != nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "exceeds") {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("oversized outbound issued %d writes", writes)
	}
	persisted, readErr := p.Stateful().ReadReceipts(payload.EngagementID)
	if readErr != nil || len(persisted) != 0 {
		t.Fatalf("oversized outbound persisted receipts = %d, %v", len(persisted), readErr)
	}
}

func TestContextForgeDescriptionBodyBoundIncludesJSONEscaping(t *testing.T) {
	overhead := len(`{"description":""}`)
	exact := strings.Repeat("x", int(contextForgeMaxRequestBytes)-overhead)
	body, err := marshalDescriptionBody(exact)
	if err != nil || int64(len(body)) != contextForgeMaxRequestBytes {
		t.Fatalf("exact-bound body = %d bytes, error %v", len(body), err)
	}
	if _, err := marshalDescriptionBody(exact + "x"); err == nil {
		t.Fatal("one-byte oversized body was accepted")
	}
	quotes := strings.Repeat(`"`, (int(contextForgeMaxRequestBytes)-overhead)/2+1)
	if _, err := marshalDescriptionBody(quotes); err == nil {
		t.Fatal("JSON escaping expansion bypassed the encoded request bound")
	}
}

func TestContextForgeExactRequestBoundStillFitsObservationAndRecoveryBounds(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	payload := fixture.payload("ENG-REQUEST-BOUND-E2E", false)
	overhead := len(`{"description":""}`)
	payload.InjectionContent = strings.Repeat("x", int(contextForgeMaxRequestBytes)-overhead)
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if err != nil {
		t.Fatalf("exact-bound Poison: %v", err)
	}
	if err := p.Revert(context.Background(), receipt); err != nil {
		t.Fatalf("exact-bound Revert: %v", err)
	}
	record, writes := fixture.snapshot()
	if writes != 2 || record.Description != testOriginal {
		t.Fatalf("exact-bound roundtrip state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRejectsUpdateWithoutExactToolResponseHeadroom(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.toolResponsePadding = int(contextForgeMaxResponseBytes - contextForgeMaxRequestBytes)
	p := newTestPoisoner(t)
	payload := fixture.payload("ENG-RESPONSE-HEADROOM", false)
	payload.InjectionContent = strings.Repeat("x", int(contextForgeMaxRequestBytes)-len(`{"description":""}`))
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if receipt != nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "headroom") {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("insufficient response headroom issued %d writes", writes)
	}
	persisted, readErr := p.Stateful().ReadReceipts(payload.EngagementID)
	if readErr != nil || len(persisted) != 0 {
		t.Fatalf("insufficient response headroom persisted receipts = %d, %v", len(persisted), readErr)
	}
}

func TestContextForgeRejectsOriginalDescriptionOutsideRestoreRequestBound(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	largeOriginal := strings.Repeat("x", int(contextForgeMaxRequestBytes))
	fixture.mu.Lock()
	fixture.record.Description = largeOriginal
	fixture.mu.Unlock()
	fixture.setMCPDescription(largeOriginal)
	p := newTestPoisoner(t)
	payload := fixture.payload("ENG-RESTORE-BOUND", false)
	payload.InjectionContent = "short replacement"
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if receipt != nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "safely restored") {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("unrestorable original issued %d writes", writes)
	}
	persisted, readErr := p.Stateful().ReadReceipts(payload.EngagementID)
	if readErr != nil || len(persisted) != 0 {
		t.Fatalf("unrestorable original persisted receipts = %d, %v", len(persisted), readErr)
	}
}

func TestContextForgeRejectsRepeatedSameToolReceiptWithinEngagement(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	engagement := "ENG-ONE-LIVE-TOOL"
	if _, err := p.Poison(context.Background(), fixture.target(), fixture.payload(engagement, false)); err != nil {
		t.Fatalf("first Poison: %v", err)
	}
	second := fixture.payload(engagement, false)
	second.InjectionContent = "second mutation"
	receipt, err := p.Poison(context.Background(), fixture.target(), second)
	if receipt != nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "unrestored") {
		t.Fatalf("second Poison = receipt %+v, error %v", receipt, err)
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != testUpdated {
		t.Fatalf("second poison state = %+v, writes=%d", record, writes)
	}
	persisted, readErr := p.Stateful().ReadReceipts(engagement)
	if readErr != nil || len(persisted) != 1 {
		t.Fatalf("persisted receipts = %d, %v", len(persisted), readErr)
	}
}

func TestContextForgeAllowsSameEngagementToolAfterVerifiedRestoration(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	engagement := "ENG-RESTORED-REUSE"
	first, err := p.Poison(context.Background(), fixture.target(), fixture.payload(engagement, false))
	if err != nil {
		t.Fatalf("first Poison: %v", err)
	}
	if err := p.Revert(context.Background(), first); err != nil {
		t.Fatalf("first Revert: %v", err)
	}
	secondPayload := fixture.payload(engagement, false)
	secondPayload.InjectionContent = "second mutation after restoration"
	second, err := p.Poison(context.Background(), fixture.target(), secondPayload)
	if err != nil {
		t.Fatalf("second Poison after restoration: %v", err)
	}
	if err := p.Revert(context.Background(), second); err != nil {
		t.Fatalf("second Revert: %v", err)
	}
	if err := p.Revert(context.Background(), first); err != nil {
		t.Fatalf("older receipt should be an original-state no-op: %v", err)
	}
	record, writes := fixture.snapshot()
	if writes != 4 || record.Description != testOriginal {
		t.Fatalf("reused engagement state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRejectsUnrestoredForwardAcrossEngagements(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	if _, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-STACK-ONE", false)); err != nil {
		t.Fatalf("first Poison: %v", err)
	}
	secondPayload := fixture.payload("ENG-STACK-TWO", false)
	secondPayload.InjectionContent = "cross-engagement mutation"
	receipt, err := p.Poison(context.Background(), fixture.target(), secondPayload)
	if receipt != nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "unrestored") {
		t.Fatalf("cross-engagement Poison = receipt %+v, error %v", receipt, err)
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != testUpdated {
		t.Fatalf("cross-engagement stack state = %+v, writes=%d", record, writes)
	}
	persisted, readErr := p.Stateful().ReadReceipts(secondPayload.EngagementID)
	if readErr != nil || len(persisted) != 0 {
		t.Fatalf("cross-engagement rejection persisted receipts = %d, %v", len(persisted), readErr)
	}
}

func TestContextForgeDryRunRejectsUnrestoredForwardAttributedRow(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	if _, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-DRY-LIVE-ONE", false)); err != nil {
		t.Fatalf("committed Poison: %v", err)
	}
	payload := fixture.payload("ENG-DRY-LIVE-TWO", true)
	payload.InjectionContent = "second dry-run mutation"
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if receipt != nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "unrestored") {
		t.Fatalf("dry-run Poison = receipt %+v, error %v", receipt, err)
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != testUpdated {
		t.Fatalf("dry-run eligibility state = %+v, writes=%d", record, writes)
	}
	persisted, readErr := p.Stateful().ReadReceipts(payload.EngagementID)
	if readErr != nil || len(persisted) != 0 {
		t.Fatalf("rejected dry-run persisted receipts = %d, %v", len(persisted), readErr)
	}
}

func TestContextForgePreflightFailuresWriteNothing(t *testing.T) {
	t.Run("association mismatch", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.associationBody = `[{"id":"44444444444444448444444444444444","name":"support-lookup","description":"different","version":1,"ownerEmail":"operator@example.com","teamId":"33333333333343338333333333333333"}]`
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-MISMATCH", false))
		if err == nil || !strings.Contains(err.Error(), "association") {
			t.Fatalf("error = %v", err)
		}
		_, writes := fixture.snapshot()
		if writes != 0 {
			t.Fatalf("preflight issued %d writes", writes)
		}
	})

	t.Run("server identity mismatch", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.serverResponseID = "55555555555545558555555555555555"
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-SERVER", false))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "server identity mismatch") {
			t.Fatalf("error = %v", err)
		}
		_, writes := fixture.snapshot()
		if writes != 0 {
			t.Fatalf("server mismatch issued %d writes", writes)
		}
	})

	t.Run("owner mismatch", func(t *testing.T) {
		t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", testJWT(t,
			[]string{"*"}, "other@example.com", false,
		))
		fixture := newContextForgeFixture(t)
		fixture.profileEmail = "other@example.com"
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-OWNER", false))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "owner") {
			t.Fatalf("error = %v", err)
		}
		_, writes := fixture.snapshot()
		if writes != 0 {
			t.Fatalf("owner mismatch issued %d writes", writes)
		}
	})

	t.Run("exact-scoped API cannot prove provider RBAC", func(t *testing.T) {
		t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", testJWT(t,
			[]string{"servers.read", "tools.read", "tools.update"}, testOwner, false, testTeamID,
		))
		fixture := newContextForgeFixture(t)
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-PERMS", false))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission ceiling") {
			t.Fatalf("error = %v", err)
		}
		_, writes := fixture.snapshot()
		if writes != 0 {
			t.Fatalf("permission mismatch issued %d writes", writes)
		}
	})

	t.Run("session effective permission missing", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.effectivePermissions = []string{"servers.read", "tools.read"}
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-SESSION-PERMS", false))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "tools.update") {
			t.Fatalf("error = %v", err)
		}
		_, writes := fixture.snapshot()
		if writes != 0 {
			t.Fatalf("session permission mismatch issued %d writes", writes)
		}
	})

	t.Run("team membership is not ownership", func(t *testing.T) {
		t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", testJWT(t,
			[]string{"*"}, "teammate@example.com", false, testTeamID,
		))
		fixture := newContextForgeFixture(t)
		fixture.profileEmail = "teammate@example.com"
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-TEAM", true))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "direct ownership") {
			t.Fatalf("team membership error = %v", err)
		}
		_, writes := fixture.snapshot()
		if writes != 0 {
			t.Fatalf("team membership mismatch issued %d writes", writes)
		}
	})

	t.Run("wildcard API token proves provider profile and effective RBAC", func(t *testing.T) {
		t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", testJWT(t,
			[]string{"*"}, testOwner, false,
		))
		fixture := newContextForgeFixture(t)
		receipt, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-API", true))
		if err != nil || receipt == nil {
			t.Fatalf("API-token preflight = receipt %+v, error %v", receipt, err)
		}
		fixture.mu.Lock()
		permissionTeamIDs := append([]string(nil), fixture.permissionTeamIDs...)
		fixture.mu.Unlock()
		if len(permissionTeamIDs) == 0 {
			t.Fatal("API-token preflight did not query provider effective RBAC")
		}
		for _, teamID := range permissionTeamIDs {
			if teamID != testTeamID {
				t.Fatalf("permission query team_id = %q, want %q", teamID, testTeamID)
			}
		}
	})

	t.Run("platform admin uses authenticated bypass without role assignments", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.profileEmail = "admin@example.com"
		fixture.profileAdmin = true
		fixture.effectivePermissions = nil
		receipt, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-ADMIN", true))
		if err != nil || receipt == nil {
			t.Fatalf("admin preflight = receipt %+v, error %v", receipt, err)
		}
		fixture.mu.Lock()
		permissionQueries := len(fixture.permissionTeamIDs)
		fixture.mu.Unlock()
		if permissionQueries != 0 {
			t.Fatalf("admin preflight made %d unnecessary effective-role queries", permissionQueries)
		}
	})

	t.Run("session token resolves provider profile", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.profileEmail = "other@example.com"
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-SESSION", true))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "direct ownership") {
			t.Fatalf("session profile mismatch error = %v", err)
		}
	})
}

func TestContextForgeNormalizationIsCleanedUpWithoutRepeatingForwardWrite(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.normalize = func(value string) string {
		if value == testUpdated {
			return strings.ToUpper(value)
		}
		return value
	}
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-NORMALIZED", false))
	if receipt == nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "normalized") {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}
	record, writes := fixture.snapshot()
	if writes != 2 || record.Description != testOriginal {
		t.Fatalf("normalization cleanup state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeNormalizedResponseLossRecoversFromPreparedReceiptAfterInlineCleanupFails(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.normalize = func(value string) string {
		if value == testUpdated {
			return strings.ToUpper(value)
		}
		return value
	}
	fixture.dropWriteBody = true
	fixture.rejectPutAttempt = 2
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-NORMALIZED-LOSS", false))
	if receipt == nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "cleanup failed") {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != strings.ToUpper(testUpdated) ||
		record.Version != 2 || record.ModifiedUserAgent != receipt.ContextForge.Management.ForwardUserAgent {
		t.Fatalf("prepared recovery state = %+v, writes=%d", record, writes)
	}

	fixture.dropWriteBody = false
	if err := p.Revert(context.Background(), receipt); err != nil {
		t.Fatalf("Revert normalized response-loss state: %v", err)
	}
	record, writes = fixture.snapshot()
	if writes != 2 || record.Description != testOriginal || record.Version != 3 ||
		record.ModifiedUserAgent != receipt.ContextForge.Management.RestoreUserAgent {
		t.Fatalf("recovered state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRevertCompletesRestoreWhenForwardNormalizationLandsOriginalText(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.normalize = func(value string) string {
		if value == testUpdated {
			return testOriginal
		}
		return value
	}
	fixture.rejectPutAttempt = 2
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-NORMALIZED-ORIGINAL", false))
	if receipt == nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "cleanup failed") {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != testOriginal || record.Version != 2 ||
		record.ModifiedUserAgent != receipt.ContextForge.Management.ForwardUserAgent {
		t.Fatalf("forward-attributed original-looking state = %+v, writes=%d", record, writes)
	}

	if err := p.Revert(context.Background(), receipt); err != nil {
		t.Fatalf("Revert forward-attributed original-looking state: %v", err)
	}
	record, writes = fixture.snapshot()
	if writes != 2 || record.Description != testOriginal || record.Version != 3 ||
		record.ModifiedUserAgent != receipt.ContextForge.Management.RestoreUserAgent {
		t.Fatalf("completed restoration state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRevertReportsProviderRejectionWithoutClaimingRecovery(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.rejectPutAttempt = 2
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-RESTORE-REJECTED", false))
	if err != nil || receipt == nil {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}

	err = p.Revert(context.Background(), receipt)
	if err == nil {
		t.Fatal("Revert reported success after the provider rejected restoration")
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != testUpdated || record.Version != 2 ||
		record.ModifiedUserAgent != receipt.ContextForge.Management.ForwardUserAgent {
		t.Fatalf("rejected restoration state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeWriteResponseLossReconcilesWithoutSecondForwardWrite(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.dropWriteBody = true
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-RECONCILE", false))
	if err != nil {
		t.Fatalf("Poison: %v", err)
	}
	if receipt == nil {
		t.Fatal("missing receipt")
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Description != testUpdated {
		t.Fatalf("reconciled state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRevertRejectsUnownedAndDivergentStateWithoutWriting(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-CONFLICT", false))
	if err != nil {
		t.Fatal(err)
	}

	fixture.mu.Lock()
	fixture.record.Description = "third-party"
	fixture.record.Version++
	fixture.record.ModifiedUserAgent = "other-client"
	fixture.mu.Unlock()
	fixture.setMCPDescription("third-party")
	_, before := fixture.snapshot()
	err = p.Revert(context.Background(), receipt)
	if !errors.Is(err, action.ErrRevertConflict) {
		t.Fatalf("Revert error = %v, want conflict", err)
	}
	_, after := fixture.snapshot()
	if after != before {
		t.Fatalf("conflict issued a write: %d -> %d", before, after)
	}

	fixture.setMCPDescription("divergent")
	err = p.Revert(context.Background(), receipt)
	if !errors.Is(err, action.ErrRevertIndeterminate) {
		t.Fatalf("divergent error = %v, want indeterminate", err)
	}
	_, afterDivergent := fixture.snapshot()
	if afterDivergent != after {
		t.Fatal("divergent state issued a write")
	}
}

func TestContextForgeRevertTreatsProviderTeamDriftAsConflict(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-TEAM-DRIFT", false))
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.record.TeamID = "55555555555545558555555555555555"
	fixture.mu.Unlock()
	_, before := fixture.snapshot()
	err = p.Revert(context.Background(), receipt)
	if !errors.Is(err, action.ErrRevertConflict) {
		t.Fatalf("Revert error = %v, want conflict", err)
	}
	_, after := fixture.snapshot()
	if after != before {
		t.Fatalf("team drift issued a write: %d -> %d", before, after)
	}
}

func TestContextForgeRevertRejectsExactRowIdentityMismatchWithoutWriting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*contextForgeTool)
		want   error
	}{
		{
			name: "different UUID",
			mutate: func(tool *contextForgeTool) {
				tool.ID = "55555555555545558555555555555555"
			},
			want: action.ErrRevertIndeterminate,
		},
		{
			name: "different name",
			mutate: func(tool *contextForgeTool) {
				tool.Name = "renamed-tool"
			},
			want: action.ErrRevertConflict,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizeFixture(t)
			fixture := newContextForgeFixture(t)
			p := newTestPoisoner(t)
			receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-ROW-IDENTITY", false))
			if err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			tc.mutate(&fixture.record)
			fixture.mu.Unlock()
			_, before := fixture.snapshot()
			err = p.Revert(context.Background(), receipt)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Revert error = %v, want %v", err, tc.want)
			}
			_, after := fixture.snapshot()
			if after != before {
				t.Fatalf("identity mismatch issued a write: %d -> %d", before, after)
			}
		})
	}
}

func TestContextForgeRevertDetectsProviderTeamDriftDuringStabilization(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-TEAM-DRIFT-POLL", true))
	if err != nil {
		t.Fatal(err)
	}
	receipt.DryRun = false
	fixture.mu.Lock()
	fixture.toolReads = 0
	fixture.onToolRead = func(readNumber int) {
		if readNumber != 2 {
			return
		}
		fixture.mu.Lock()
		fixture.record.TeamID = "55555555555545558555555555555555"
		fixture.mu.Unlock()
	}
	fixture.mu.Unlock()
	err = p.Revert(context.Background(), receipt)
	if !errors.Is(err, action.ErrRevertConflict) {
		t.Fatalf("Revert error = %v, want conflict", err)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("team drift during stabilization issued %d writes", writes)
	}
}

func TestContextForgeRevertPreservesNameConflictDuringStabilization(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-NAME-DRIFT-POLL", true))
	if err != nil {
		t.Fatal(err)
	}
	receipt.DryRun = false
	fixture.setMCPDescription("temporarily divergent")
	fixture.mu.Lock()
	fixture.toolReads = 0
	fixture.onToolRead = func(readNumber int) {
		if readNumber != 2 {
			return
		}
		fixture.mu.Lock()
		fixture.record.Name = "renamed-tool"
		fixture.mu.Unlock()
	}
	fixture.mu.Unlock()
	err = p.Revert(context.Background(), receipt)
	if !errors.Is(err, action.ErrRevertConflict) {
		t.Fatalf("Revert error = %v, want conflict", err)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("name drift during stabilization issued %d writes", writes)
	}
}

func TestContextForgeRevertRejectsUnchangedDescriptionWithMissingOrRewrittenAttribution(t *testing.T) {
	for _, userAgent := range []string{"", "other-client"} {
		t.Run(fmt.Sprintf("user_agent_%q", userAgent), func(t *testing.T) {
			authorizeFixture(t)
			fixture := newContextForgeFixture(t)
			p := newTestPoisoner(t)
			receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-ATTRIBUTION", false))
			if err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			fixture.record.Version++
			fixture.record.ModifiedUserAgent = userAgent
			fixture.mu.Unlock()
			_, before := fixture.snapshot()
			err = p.Revert(context.Background(), receipt)
			if !errors.Is(err, action.ErrRevertConflict) {
				t.Fatalf("Revert error = %v, want conflict", err)
			}
			_, after := fixture.snapshot()
			if after != before {
				t.Fatalf("unattributed state issued a write: %d -> %d", before, after)
			}
		})
	}
}

func TestContextForgeConcurrentUpdateInForwardTOCTOUIsIndeterminateWithoutCleanup(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.onWrite = func() {
		fixture.mu.Lock()
		fixture.record.Description = "concurrent administrator value"
		fixture.record.Version++
		fixture.record.ModifiedUserAgent = "administrator"
		fixture.mu.Unlock()
	}
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-FORWARD-TOCTOU", false))
	if receipt == nil || !errors.Is(err, action.ErrRevertIndeterminate) {
		t.Fatalf("Poison result = receipt %+v, error %v", receipt, err)
	}
	record, writes := fixture.snapshot()
	if writes != 1 || record.Version != 3 || record.Description != testUpdated {
		t.Fatalf("TOCTOU state = %+v, writes=%d; cleanup must not run without V+1 attribution", record, writes)
	}
}

func TestContextForgeAssociationReadErrorRequiresDualSurfaceCleanupVerification(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.skipMCPUpdateAttempt = 2
	fixture.onWrite = func() {
		fixture.mu.Lock()
		fixture.associationBody = `{malformed`
		fixture.mu.Unlock()
	}
	p := newTestPoisoner(t)
	payload := fixture.payload("ENG-ASSOCIATION-UNKNOWN", false)
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if receipt == nil || !errors.Is(err, action.ErrRevertIndeterminate) {
		t.Fatalf("Poison = receipt %+v, error %v; want indeterminate", receipt, err)
	}
	if strings.Contains(err.Error(), "AgentHound restored the original") {
		t.Fatalf("error falsely claimed complete restoration: %v", err)
	}
	record, writes := fixture.snapshot()
	if writes != 2 || record.Description != testOriginal || record.Version != 3 {
		t.Fatalf("management cleanup state = %+v, writes=%d", record, writes)
	}
	config, parseErr := parseContextForgeConfig(fixture.target(), testToolName, payload.Extras)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	observed, observeErr := p.observeMCP(context.Background(), config)
	if observeErr != nil {
		t.Fatal(observeErr)
	}
	if observed.Description != testUpdated {
		t.Fatalf("MCP description = %q, want stale mutation %q", observed.Description, testUpdated)
	}
}

func TestContextForgeRevertRestoresAttributedRowAfterAssociationDrift(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-DETACHED", false))
	if err != nil {
		t.Fatal(err)
	}
	fixture.associationBody = `[]`
	fixture.mcpHTTP.Close()
	if err := p.Revert(context.Background(), receipt); !errors.Is(err, action.ErrRevertPartiallyVerified) {
		t.Fatalf("Revert detached attributed row = %v, want partial verification", err)
	}
	record, writes := fixture.snapshot()
	if writes != 2 || record.Description != testOriginal ||
		record.ModifiedUserAgent != receipt.ContextForge.Management.RestoreUserAgent {
		t.Fatalf("detached restoration = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRevertRestoresAttributedRowAfterSameNameRebind(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-REBOUND", false))
	if err != nil {
		t.Fatal(err)
	}
	fixture.associationBody = `[{"id":"44444444444444448444444444444444","name":"support-lookup","description":"replacement row","version":1}]`
	fixture.mcpHTTP.Close()
	if err := p.Revert(context.Background(), receipt); !errors.Is(err, action.ErrRevertPartiallyVerified) {
		t.Fatalf("Revert rebound attributed row = %v, want partial verification", err)
	}
	record, writes := fixture.snapshot()
	if writes != 2 || record.Description != testOriginal ||
		record.ModifiedUserAgent != receipt.ContextForge.Management.RestoreUserAgent {
		t.Fatalf("rebound restoration = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRevertPollsOriginalBeforeNoOpForDelayedForwardCommit(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-DELAYED", true))
	if err != nil {
		t.Fatal(err)
	}
	receipt.DryRun = false
	fixture.mu.Lock()
	fixture.toolReads = 0
	fixture.onToolRead = func(readNumber int) {
		if readNumber != 2 {
			return
		}
		fixture.mu.Lock()
		fixture.record.Description = testUpdated
		fixture.record.Version = 2
		fixture.record.ModifiedUserAgent = receipt.ContextForge.Management.ForwardUserAgent
		fixture.writes++
		fixture.mu.Unlock()
		fixture.setMCPDescription(testUpdated)
	}
	fixture.mu.Unlock()
	if err := p.Revert(context.Background(), receipt); err != nil {
		t.Fatalf("Revert delayed commit: %v", err)
	}
	record, writes := fixture.snapshot()
	if writes != 2 || record.Description != testOriginal || record.Version != 3 {
		t.Fatalf("delayed restoration = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeFinalPreflightDetectsDriftBeforeReceiptOrWrite(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.onToolRead = func(readNumber int) {
		if readNumber != 2 {
			return
		}
		fixture.mu.Lock()
		fixture.record.Version++
		fixture.record.ModifiedUserAgent = "other-client"
		fixture.mu.Unlock()
	}
	p := newTestPoisoner(t)
	receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-DRIFT", false))
	if receipt != nil || err == nil {
		t.Fatalf("result = receipt %+v, error %v", receipt, err)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("final preflight drift issued %d writes", writes)
	}
	if _, statErr := os.Stat(filepath.Join(p.Stateful().StateDir(), "ENG-DRIFT.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("final preflight drift persisted receipt: %v", statErr)
	}
}

func TestContextForgeRevertRejectsMissingTypedReceiptBeforeNetworking(t *testing.T) {
	t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", "")
	err := newTestPoisoner(t).Revert(context.Background(), &action.PoisonReceipt{
		ModuleID: "mcp.poison", EngagementID: "ENG-UNTYPED",
		OriginalContent: testOriginal, InjectedContent: testUpdated,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "typed") {
		t.Fatalf("error = %v", err)
	}
}

func TestContextForgeHTTPContractRejectsRedirectAndNonJSON(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)

	destinationHits := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationHits++
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	payload := fixture.payload("ENG-REDIRECT", false)
	payload.Extras["management-url"] = redirect.URL
	_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), payload)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "redirect") || destinationHits != 0 {
		t.Fatalf("redirect result: err=%v destination_hits=%d", err, destinationHits)
	}

	fixture.contentType = "text/html"
	_, err = newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-HTML", false))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "content type") {
		t.Fatalf("content-type error = %v", err)
	}
}

func TestContextForgeRejectsNullDescriptionBeforeMutation(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.associationBody = `[{"id":"` + testToolID + `","name":"` + testToolName + `","description":null,"version":1,"ownerEmail":"` + testOwner + `"}]`
	receipt, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-NULL", false))
	if receipt != nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "description") {
		t.Fatalf("result = receipt %+v, error %v", receipt, err)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("null description issued %d writes", writes)
	}
}

func TestContextForgeHTTPContractRejectsOversizeAndUnexpectedWriteStatus(t *testing.T) {
	t.Run("oversized read", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.associationBody = `[` + strings.Repeat(" ", int(contextForgeMaxResponseBytes)) + `]`
		_, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-OVERSIZE", false))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "exceeds") {
			t.Fatalf("error = %v", err)
		}
		_, writes := fixture.snapshot()
		if writes != 0 {
			t.Fatalf("oversized preflight issued %d writes", writes)
		}
	})

	t.Run("unexpected write status", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.writeStatus = http.StatusCreated
		receipt, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-STATUS", false))
		if receipt == nil || err == nil || !strings.Contains(err.Error(), "expected 200") {
			t.Fatalf("result = receipt %+v, error %v", receipt, err)
		}
		if errors.Is(err, action.ErrRevertIndeterminate) {
			t.Fatalf("verified exact cleanup was reported indeterminate: %v", err)
		}
		record, writes := fixture.snapshot()
		if writes != 2 || record.Description != testOriginal {
			t.Fatalf("contract cleanup state = %+v, writes=%d", record, writes)
		}
	})
}

func TestContextForgeDefinitiveWriteRejectionReportsUnchangedState(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	fixture.rejectPutAttempt = 1
	fixture.rejectPutStatus = http.StatusForbidden
	receipt, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-REJECTED", false))
	if receipt == nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "remained unchanged") {
		t.Fatalf("result = receipt %+v, error %v", receipt, err)
	}
	if errors.Is(err, action.ErrRevertIndeterminate) {
		t.Fatalf("definitively rejected unchanged write reported indeterminate: %v", err)
	}
	record, writes := fixture.snapshot()
	if writes != 0 || record.Description != testOriginal || record.Version != 1 {
		t.Fatalf("rejected write state = %+v, writes=%d", record, writes)
	}
}

func TestContextForgeRejectsMismatchedSuccessfulWriteResponses(t *testing.T) {
	t.Run("forward", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		fixture.writeResponse = func(attempt int, record contextForgeTool) contextForgeTool {
			if attempt == 1 {
				record.Version--
				record.ModifiedUserAgent = "stale-response"
			}
			return record
		}
		receipt, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-STALE-FORWARD", false))
		if receipt == nil || err == nil || !strings.Contains(strings.ToLower(err.Error()), "violated the fixed contract") {
			t.Fatalf("result = receipt %+v, error %v", receipt, err)
		}
		record, writes := fixture.snapshot()
		if writes != 2 || record.Description != testOriginal {
			t.Fatalf("forward contract cleanup state = %+v, writes=%d", record, writes)
		}
	})

	t.Run("restore", func(t *testing.T) {
		authorizeFixture(t)
		fixture := newContextForgeFixture(t)
		p := newTestPoisoner(t)
		receipt, err := p.Poison(context.Background(), fixture.target(), fixture.payload("ENG-STALE-RESTORE", false))
		if err != nil {
			t.Fatal(err)
		}
		fixture.writeResponse = func(attempt int, record contextForgeTool) contextForgeTool {
			if attempt == 2 {
				record.Version--
				record.ModifiedUserAgent = "stale-response"
			}
			return record
		}
		err = p.Revert(context.Background(), receipt)
		if err != nil {
			t.Fatalf("Revert should trust exact independent restoration read-back: %v", err)
		}
		record, writes := fixture.snapshot()
		if writes != 2 || record.Description != testOriginal {
			t.Fatalf("restore contract state = %+v, writes=%d", record, writes)
		}
	})
}

func TestContextForgeCredentialsAreIndependentAndNeverPersisted(t *testing.T) {
	authorizeFixture(t)
	p := newTestPoisoner(t)
	t.Setenv("AGENTHOUND_MCP_TOKEN", "mcp-only-secret")
	fixture := newContextForgeFixture(t)
	fixture.expectedMCPAuth = "Bearer mcp-only-secret"
	target := fixture.target()
	target.Meta = map[string]string{"url": target.Address, "Authorization": "meta-only-secret"}
	receipt, err := p.Poison(context.Background(), target, fixture.payload("ENG-CREDS", true))
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	mcpAuthSeen := fixture.mcpAuthSeen
	fixture.mu.Unlock()
	if !mcpAuthSeen {
		t.Fatal("independent MCP credential was not used on the MCP origin")
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"mcp-only-secret", "meta-only-secret", os.Getenv("AGENTHOUND_CONTEXTFORGE_TOKEN")} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("credential persisted in receipt")
		}
	}
}

func TestContextForgeManagementCredentialFallbackIsSameOriginOnly(t *testing.T) {
	t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", "")
	t.Setenv("AGENTHOUND_MCP_TOKEN", "same-origin-bearer")
	token, err := resolveContextForgeToken(
		"https://forge.example/proxy/servers/11111111111141118111111111111111/mcp/",
		"https://forge.example/proxy",
	)
	if err != nil || token != "same-origin-bearer" {
		t.Fatalf("same-origin fallback = %q, %v", token, err)
	}
	if _, err := resolveContextForgeToken(
		"https://mcp.example/servers/11111111111141118111111111111111/mcp",
		"https://management.example",
	); err == nil || !strings.Contains(err.Error(), "different origin") {
		t.Fatalf("cross-origin fallback error = %v", err)
	}
}

func TestContextForgeObserveReceiptHonorsExplicitInsecureContext(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixtureWithTLS(t, true)
	p := newTestPoisoner(t)
	payload := fixture.payload("ENG-INSECURE", true)
	payload.Extras["insecure"] = true
	receipt, err := p.Poison(context.Background(), fixture.target(), payload)
	if err != nil {
		t.Fatalf("TLS dry-run: %v", err)
	}
	if _, err := p.ObserveReceipt(context.Background(), receipt); err == nil {
		t.Fatal("ObserveReceipt accepted an untrusted certificate without explicit insecure context")
	}
	insecureCtx := context.WithValue(context.Background(), action.RevertInsecureKey{}, true)
	observation, err := p.ObserveReceipt(insecureCtx, receipt)
	if err != nil {
		t.Fatalf("ObserveReceipt insecure: %v", err)
	}
	if !observation.Associated || !observation.MCPObserved || !observation.ManagementObserved {
		t.Fatalf("observation = %+v", observation)
	}
}

func TestContextForgeRevertRejectsUnknownTypedProfileBeforeNetworking(t *testing.T) {
	t.Setenv("AGENTHOUND_CONTEXTFORGE_TOKEN", "")
	err := newTestPoisoner(t).Revert(context.Background(), &action.PoisonReceipt{
		ModuleID: "mcp.poison", ReceiptID: "opaque", ContextForge: &action.ContextForgeToolDescriptionReceipt{
			ReceiptType: action.ContextForgeReceiptType, ReceiptVersion: action.ContextForgeReceiptVersion,
			Profile: "unknown", ContractID: action.ContextForgeContractID,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown management_profile") {
		t.Fatalf("error = %v", err)
	}
}

func TestContextForgeObservationReturnsBothSurfaces(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	observation, err := newTestPoisoner(t).Observe(
		context.Background(), fixture.target(), testToolName,
		map[string]any{
			"adapter": action.ContextForgeProfile, "management-url": fixture.managementHTTP.URL,
		},
	)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !observation.Associated || observation.MCPDescription != testOriginal ||
		observation.ManagementDescription != testOriginal || observation.ManagementVersion != 1 {
		t.Fatalf("observation = %+v", observation)
	}
}

func TestExtractContextForgeServerID(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want string
	}{
		{"https://forge.example/servers/11111111111141118111111111111111/mcp", "11111111111141118111111111111111"},
		{"https://forge.example/proxy/prefix/servers/22222222222242228222222222222222/mcp/", "22222222222242228222222222222222"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			got, err := extractContextForgeServerID(tc.url)
			if err != nil || got != tc.want {
				t.Fatalf("extract = %q, %v", got, err)
			}
		})
	}
	for _, raw := range []string{
		"https://forge.example/mcp",
		"https://forge.example/servers//mcp",
		"https://forge.example/servers/not-a-uuid/mcp",
		"https://forge.example/servers/11111111%2D1111%2D4111%2D8111%2D111111111111/mcp",
		"https://forge.example/tenant%2Fblue/servers/11111111111141118111111111111111/mcp",
		"https://forge.example/tenant/%2e%2e/servers/11111111111141118111111111111111/mcp",
		"https://forge.example/tenant//servers/11111111111141118111111111111111/mcp",
		"https://forge.example/servers/11111111111141118111111111111111/mcp?x=1",
	} {
		t.Run(fmt.Sprintf("reject_%s", raw), func(t *testing.T) {
			if _, err := extractContextForgeServerID(raw); err == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
}

func TestContextForgeManagementBaseRejectsAmbiguousPathSegments(t *testing.T) {
	for _, raw := range []string{
		"https://forge.example/tenant//blue",
		"https://forge.example/tenant%2Fblue",
		"https://forge.example/tenant/%2e%2e",
		"https://forge.example/tenant/../blue",
	} {
		if _, err := validateManagementBase(raw); err == nil {
			t.Fatalf("accepted ambiguous management base %q", raw)
		}
	}
}

func TestContextForgeMCPURLPreservesTrailingSlashForExactCredentialLookup(t *testing.T) {
	raw := "https://forge.example/proxy/servers/11111111111141118111111111111111/mcp/"
	parsed, serverID, base, err := parseContextForgeMCPURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != raw || serverID != testServerID || base != "https://forge.example/proxy" {
		t.Fatalf("parsed=%q server=%q base=%q", parsed, serverID, base)
	}
}

func TestDryRunProducesTypedReceiptWithoutWrite(t *testing.T) {
	authorizeFixture(t)
	fixture := newContextForgeFixture(t)
	receipt, err := newTestPoisoner(t).Poison(context.Background(), fixture.target(), fixture.payload("ENG-DRY", true))
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.DryRun || receipt.ContextForge == nil {
		t.Fatalf("receipt = %+v", receipt)
	}
	_, writes := fixture.snapshot()
	if writes != 0 {
		t.Fatalf("dry-run issued %d writes", writes)
	}
}

var _ = module.NewFileStatefulModule

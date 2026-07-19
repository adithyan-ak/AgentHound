package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	configmodule "github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestMCPCollectorOfficialStreamableHandlerUsesCanonicalScope(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "contract-server", Version: "1.0.0"}, nil)
	httpServer := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	))
	defer httpServer.Close()

	result, err := NewMCPCollector().Collect(context.Background(), collector.CollectOptions{
		TargetURL: httpServer.URL, ScanID: "canonical-contract",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wantKey := mcpCoverageKey(ServerSpec{Transport: "http", URL: httpServer.URL})
	if len(result.Meta.Collection.CoverageKeys) != 1 || result.Meta.Collection.CoverageKeys[0] != wantKey {
		t.Fatalf("coverage keys = %v, want [%s]", result.Meta.Collection.CoverageKeys, wantKey)
	}
	methods := make(map[string]bool)
	for _, outcome := range result.Meta.Collection.Outcomes {
		if outcome.CoverageKey != wantKey || outcome.Target != httpServer.URL {
			t.Fatalf("non-canonical outcome = %+v", outcome)
		}
		if methods[outcome.Method] {
			t.Fatalf("duplicate method outcome %q", outcome.Method)
		}
		methods[outcome.Method] = true
	}
	for _, node := range result.Graph.Nodes {
		if len(node.ObservationDomains) != 1 || node.ObservationDomains[0] != wantKey {
			t.Fatalf("node %s domains = %v, want [%s]", node.ID, node.ObservationDomains, wantKey)
		}
		if ingest.ConcreteNodeKind(node.Kinds) == "MCPServer" {
			for property, want := range map[string]any{
				"observed_auth_method":    string(common.AuthNone),
				"observed_auth_assurance": string(common.AuthAssuranceUnauthenticated),
				"observed_auth_evidence":  common.AuthEvidenceAnonymousProbeSucceeded,
			} {
				if got := node.Properties[property]; got != want {
					t.Errorf("header-free %s = %v, want %v", property, got, want)
				}
			}
		}
	}
}

func TestMCPCollectorCookieGatedInitializeCannotClaimAnonymous(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "cookie-gated-server", Version: "1.0.0"}, nil)
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	)
	const cookieValue = "session=COOKIE-GATED-OPAQUE-VALUE"
	var accepted atomic.Int64
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cookie") != cookieValue {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		accepted.Add(1)
		mcpHandler.ServeHTTP(w, request)
	}))
	defer httpServer.Close()

	configPath := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	configDocument := map[string]any{
		"mcpServers": map[string]any{
			"cookie-gated": map[string]any{
				"url": httpServer.URL,
				"headers": map[string]string{
					"Cookie": cookieValue,
				},
			},
		},
	}
	encoded, err := json.Marshal(configDocument)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewMCPCollector().Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "cookie-gated-auth-truth",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if accepted.Load() == 0 {
		t.Fatal("configured Cookie did not reach the real MCP Initialize handler")
	}
	if result.Meta.Collection == nil {
		t.Fatal("cookie-gated collection omitted collection metadata")
	}
	initializeComplete := false
	for _, outcome := range result.Meta.Collection.Outcomes {
		if outcome.Method == "initialize" && outcome.State == ingest.OutcomeComplete {
			initializeComplete = true
			break
		}
	}
	if !initializeComplete {
		t.Fatalf("cookie-gated Initialize was not complete: %+v", result.Meta.Collection)
	}

	var observedServer *ingest.Node
	for i := range result.Graph.Nodes {
		if ingest.ConcreteNodeKind(result.Graph.Nodes[i].Kinds) == "MCPServer" {
			observedServer = &result.Graph.Nodes[i]
			break
		}
	}
	if observedServer == nil {
		t.Fatal("cookie-gated collection emitted no MCPServer")
	}
	if got := observedServer.Properties["observed_auth_method"]; got != string(common.AuthUnknown) {
		t.Fatalf("cookie-gated observed method = %v, want unknown", got)
	}
	if got := observedServer.Properties["observed_auth_assurance"]; got != string(common.AuthAssuranceUnknown) {
		t.Fatalf("cookie-gated observed assurance = %v, want unknown", got)
	}
	if got := observedServer.Properties["observed_auth_evidence"]; got != common.AuthEvidenceConfiguredCredential {
		t.Fatalf("cookie-gated observed evidence = %v, want configured credential", got)
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if strings.Contains(string(serialized), cookieValue) {
		t.Fatalf("cookie material leaked into collection artifact: %s", serialized)
	}
}

func TestMCPCollectorPreservesSharedHostPerTargetDomain(t *testing.T) {
	servers := make([]*httptest.Server, 0, 2)
	targets := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		server := mcp.NewServer(
			&mcp.Implementation{Name: "shared-host-server", Version: "1.0.0"},
			nil,
		)
		httpServer := httptest.NewServer(mcp.NewStreamableHTTPHandler(
			func(*http.Request) *mcp.Server { return server },
			&mcp.StreamableHTTPOptions{JSONResponse: true},
		))
		servers = append(servers, httpServer)
		targets = append(targets, httpServer.URL)
	}
	for _, server := range servers {
		defer server.Close()
	}

	result, err := NewMCPCollector().Collect(
		context.Background(),
		collector.CollectOptions{TargetURLs: targets, ScanID: "shared-host-targets"},
	)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	wantDomains := map[string]bool{
		mcpCoverageKey(ServerSpec{Transport: "http", URL: targets[0]}): true,
		mcpCoverageKey(ServerSpec{Transport: "http", URL: targets[1]}): true,
	}
	observedDomains := make(map[string]bool)
	for _, node := range result.Graph.Nodes {
		if ingest.ConcreteNodeKind(node.Kinds) != "Host" ||
			len(node.ObservationDomains) != 1 {
			continue
		}
		domain := node.ObservationDomains[0]
		if wantDomains[domain] {
			observedDomains[domain] = true
		}
	}
	if len(observedDomains) != 2 {
		t.Fatalf("shared host contributions = %v, want one per MCP target", observedDomains)
	}
}

func TestMCPContributionDedupPreservesDistinctSameOwnerFragments(t *testing.T) {
	base := ingest.Edge{
		Source: "server", Kind: "RUNS_ON", Target: "host",
		SourceKind: "MCPServer", TargetKind: "Host",
		ObservationDomains: []string{"mcp:target:sha256:owner"},
		Properties:         map[string]any{"confidence": 1.0},
	}
	exactKey, exactComparable := mcpEdgeContributionDedupKey(base)
	duplicateKey, duplicateComparable := mcpEdgeContributionDedupKey(base)
	changed := base
	changed.Properties = map[string]any{"confidence": 0.5}
	changedKey, changedComparable := mcpEdgeContributionDedupKey(changed)
	if !exactComparable || !duplicateComparable || !changedComparable {
		t.Fatal("canonical collector contributions were not comparable")
	}
	if exactKey != duplicateKey {
		t.Fatal("exact same-owner contribution was not deduplicated")
	}
	if exactKey == changedKey {
		t.Fatal("conflicting same-owner fragment would be collapsed before writer validation")
	}
}

func TestMCPCollectorOmitsUnknownResourceSize(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "resource-size-server", Version: "1.0.0"}, nil)
	server.AddResource(&mcp.Resource{
		URI:  "file:///unknown-size.txt",
		Name: "unknown-size",
	}, nil)
	server.AddResource(&mcp.Resource{
		URI:  "file:///known-size.txt",
		Name: "known-size",
		Size: 42,
	}, nil)
	httpServer := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	))
	defer httpServer.Close()

	data, err := NewMCPCollector().Collect(context.Background(), collector.CollectOptions{
		TargetURL: httpServer.URL,
		ScanID:    "resource-size-presence",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	resources := make(map[string]ingest.Node)
	var observedServer *ingest.Node
	for _, node := range data.Graph.Nodes {
		for _, kind := range node.Kinds {
			if kind == "MCPResource" {
				uri, ok := node.Properties["uri"].(string)
				if !ok {
					t.Fatalf("resource URI is not a string: %+v", node.Properties)
				}
				resources[uri] = node
			}
			if kind == "MCPServer" {
				copy := node
				observedServer = &copy
			}
		}
	}
	if observedServer == nil || observedServer.Properties["has_tasks_capability"] != false {
		t.Fatalf("absent raw tasks key was not represented as false: %+v", observedServer)
	}
	unknown := resources["file:///unknown-size.txt"]
	if _, exists := unknown.Properties["size"]; exists {
		t.Fatalf("unknown wire size was fabricated: %+v", unknown.Properties)
	}
	known := resources["file:///known-size.txt"]
	if got := known.Properties["size"]; got != int64(42) {
		t.Fatalf("known wire size = %#v, want int64(42)", got)
	}
}

func TestMCPSharedDiscoveryFailureStates(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	valid := filepath.Join(project, ".cursor", "mcp.json")
	malformed := filepath.Join(project, ".vscode", "mcp.json")
	for _, path := range []string{valid, malformed} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(valid, []byte(`{"mcpServers":{"retained":{"command":"retained-mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformed, []byte(`{"servers":`), 0o600); err != nil {
		t.Fatal(err)
	}

	collector := NewMCPCollector()
	specs, discovery, err := collector.buildServerList(context.Background(), collectoropts(true, project))
	if err != nil {
		t.Fatalf("buildServerList: %v", err)
	}
	if len(specs) != 1 || specs[0].Name != "retained" {
		t.Fatalf("retained specs = %+v", specs)
	}
	state, items, _ := summarizeConfigDiscovery(discovery)
	if state != ingest.OutcomePartial || items == 0 {
		t.Fatalf("mixed discovery = state:%s items:%d", state, items)
	}

	if err := os.Remove(valid); err != nil {
		t.Fatal(err)
	}
	specs, discovery, err = collector.buildServerList(context.Background(), collectoropts(true, project))
	if err != nil {
		t.Fatalf("failed-only buildServerList: %v", err)
	}
	state, items, _ = summarizeConfigDiscovery(discovery)
	if len(specs) != 0 || state != ingest.OutcomeFailed || items != 0 {
		t.Fatalf("failed-only discovery = specs:%v state:%s items:%d", specs, state, items)
	}
}

func TestMCPSharedDiscoveryCompleteEmptyAndInvalidRoot(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	collector := NewMCPCollector()
	specs, discovery, err := collector.buildServerList(context.Background(), collectoropts(true, project))
	if err != nil {
		t.Fatalf("complete-empty discovery: %v", err)
	}
	state, items, _ := summarizeConfigDiscovery(discovery)
	if len(specs) != 0 || state != ingest.OutcomeComplete || items != 0 {
		t.Fatalf("complete-empty = specs:%v state:%s items:%d", specs, state, items)
	}
	if _, _, err := collector.buildServerList(context.Background(), collectoropts(true, filepath.Join(project, "missing"))); err == nil {
		t.Fatal("invalid project root became complete-empty MCP discovery")
	}
}

func TestMCPDiscoveryRootDisappearsAfterValidation(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	originalResolve := resolveMCPProjectRoot
	resolveMCPProjectRoot = func(path string) (*configmodule.ValidatedProjectRoot, error) {
		root, err := originalResolve(path)
		if err == nil {
			err = os.RemoveAll(root.Path())
		}
		return root, err
	}
	t.Cleanup(func() { resolveMCPProjectRoot = originalResolve })

	result, err := NewMCPCollector().Collect(context.Background(), collectoropts(true, project))
	if err != nil {
		t.Fatalf("Collect after root disappearance: %v", err)
	}
	if result.Meta.Collection == nil || result.Meta.Collection.State != ingest.OutcomeFailed {
		t.Fatalf("collection = %+v, want failed non-authoritative discovery", result.Meta.Collection)
	}
	if len(result.Graph.Nodes) != 0 || len(result.Graph.Edges) != 0 {
		t.Fatalf("unexpected graph after root disappearance: %+v", result.Graph)
	}
	if len(result.Meta.Collection.Outcomes) != 1 ||
		result.Meta.Collection.Outcomes[0].Method != "discover_configs" ||
		result.Meta.Collection.Outcomes[0].State != ingest.OutcomeFailed {
		t.Fatalf("discovery outcomes = %+v", result.Meta.Collection.Outcomes)
	}
}

func TestMCPExplicitMissingConfigRetainsDiscoveryOutcome(t *testing.T) {
	project := t.TempDir()
	result, err := NewMCPCollector().Collect(context.Background(), collector.CollectOptions{
		ConfigPath: filepath.Join(project, "missing.json"), ProjectDir: project, ScanID: "missing-config",
	})
	if err != nil {
		t.Fatalf("Collect missing explicit config: %v", err)
	}
	if result.Meta.Collection == nil || result.Meta.Collection.State != ingest.OutcomeComplete || len(result.Graph.Nodes) != 0 {
		t.Fatalf("missing config result = %+v graph=%+v", result.Meta.Collection, result.Graph)
	}
}

func collectoropts(discover bool, project string) collector.CollectOptions {
	return collector.CollectOptions{Discover: discover, ProjectDir: project, ScanID: "discovery-state"}
}

func TestNewMCPCollectorDefaults(t *testing.T) {
	c := NewMCPCollector()

	if c.concurrency != 5 {
		t.Errorf("default concurrency: got %d, want 5", c.concurrency)
	}
	if c.timeout != 120*time.Second {
		t.Errorf("default timeout: got %v, want 120s", c.timeout)
	}
	if c.initTimeout != 30*time.Second {
		t.Errorf("default initTimeout: got %v, want 30s", c.initTimeout)
	}
	if c.maxItems != defaultMaxItems {
		t.Errorf("default maxItems: got %d, want %d", c.maxItems, defaultMaxItems)
	}
}

func TestNewMCPCollectorOptions(t *testing.T) {
	c := NewMCPCollector(
		WithConcurrency(10),
		WithTimeout(60*time.Second),
		WithInitTimeout(15*time.Second),
		WithMaxItems(5000),
	)

	if c.concurrency != 10 {
		t.Errorf("concurrency: got %d, want 10", c.concurrency)
	}
	if c.timeout != 60*time.Second {
		t.Errorf("timeout: got %v, want 60s", c.timeout)
	}
	if c.initTimeout != 15*time.Second {
		t.Errorf("initTimeout: got %v, want 15s", c.initTimeout)
	}
	if c.maxItems != 5000 {
		t.Errorf("maxItems: got %d, want 5000", c.maxItems)
	}
}

func TestNewMCPCollectorInvalidOptions(t *testing.T) {
	c := NewMCPCollector(
		WithConcurrency(-1),
		WithTimeout(-1),
		WithInitTimeout(-1),
		WithMaxItems(-1),
	)

	if c.concurrency != 5 {
		t.Errorf("expected default concurrency after invalid value, got %d", c.concurrency)
	}
	if c.timeout != 120*time.Second {
		t.Errorf("expected default timeout after invalid value, got %v", c.timeout)
	}
}

func TestMCPCollectorName(t *testing.T) {
	c := NewMCPCollector()
	if c.Name() != "mcp" {
		t.Errorf("expected 'mcp', got %q", c.Name())
	}
}

func TestCollectorInterface(t *testing.T) {
	var _ interface {
		Name() string
	} = NewMCPCollector()
}

func TestComputeServerID(t *testing.T) {
	t.Run("stdio", func(t *testing.T) {
		spec := ServerSpec{
			Transport: "stdio",
			Command:   "npx",
			Args:      []string{"-y", "@modelcontextprotocol/server-postgres"},
		}
		id := computeServerID(spec)

		expected := ingest.ComputeMCPServerID("stdio", "npx", "-y", "@modelcontextprotocol/server-postgres")
		if id != expected {
			t.Errorf("stdio server ID mismatch:\n  got  %s\n  want %s", id, expected)
		}
	})

	t.Run("http", func(t *testing.T) {
		spec := ServerSpec{
			Transport: "http",
			URL:       "http://localhost:8080/mcp",
		}
		id := computeServerID(spec)

		expected := ingest.ComputeMCPServerID("http", "http://localhost:8080/mcp")
		if id != expected {
			t.Errorf("http server ID mismatch:\n  got  %s\n  want %s", id, expected)
		}
	})

	t.Run("arg_order_sensitive_v2", func(t *testing.T) {
		spec1 := ServerSpec{Transport: "stdio", Command: "npx", Args: []string{"b", "a"}}
		spec2 := ServerSpec{Transport: "stdio", Command: "npx", Args: []string{"a", "b"}}
		if computeServerID(spec1) == computeServerID(spec2) {
			t.Error("v2 server IDs must preserve arg order")
		}
		first := serverIdentityForSpec(spec1)
		second := serverIdentityForSpec(spec2)
		if first.Scheme != ingest.MCPStdioIdentitySchemeV3 ||
			second.Scheme != ingest.MCPStdioIdentitySchemeV3 {
			t.Fatalf("reordered definitions must use hashed-argv v3 identity: %+v %+v", first, second)
		}
	})
}

func TestCollapseServerSpecsPreservesHarmlessAliasesAndRejectsAuthAmbiguity(t *testing.T) {
	alpha := ServerSpec{
		Name: "alpha", ConfiguredNames: []string{"alpha"}, Configured: true,
		Transport: "stdio", Command: "node", Args: []string{"server.js"},
		Env: map[string]string{"API_KEY": "same-secret"},
	}
	beta := alpha
	beta.Name = "beta"
	beta.ConfiguredNames = []string{"beta"}

	forward := collapseServerSpecs([]ServerSpec{beta, alpha})
	reverse := collapseServerSpecs([]ServerSpec{alpha, beta})
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("alias collapse depends on input order:\nforward=%+v\nreverse=%+v", forward, reverse)
	}
	if len(forward) != 1 || forward[0].Ambiguity != "" {
		t.Fatalf("identical aliases did not collapse safely: %+v", forward)
	}
	if want := []string{"alpha", "beta"}; !reflect.DeepEqual(forward[0].ConfiguredNames, want) {
		t.Fatalf("configured names = %v, want %v", forward[0].ConfiguredNames, want)
	}

	conflicting := beta
	conflicting.Env = map[string]string{"API_KEY": "different-secret"}
	ambiguous := collapseServerSpecs([]ServerSpec{alpha, conflicting})
	if len(ambiguous) != 1 || ambiguous[0].Ambiguity != ambiguousServerProfileError {
		t.Fatalf("credential-distinct aliases were not rejected deterministically: %+v", ambiguous)
	}
	if strings.Contains(ambiguous[0].Ambiguity, "same-secret") ||
		strings.Contains(ambiguous[0].Ambiguity, "different-secret") {
		t.Fatalf("ambiguity diagnostic leaked credential material: %q", ambiguous[0].Ambiguity)
	}
}

func TestCollapseServerSpecsCanonicalizesHTTPHeaderProfiles(t *testing.T) {
	const sharedCredential = "Bearer same-case-insensitive-value"
	alpha := ServerSpec{
		Name: "alpha", ConfiguredNames: []string{"alpha"}, Configured: true,
		Transport: "http", URL: "https://mcp.example/mcp",
		Headers: map[string]string{"Authorization": sharedCredential},
	}
	beta := alpha
	beta.Name = "beta"
	beta.ConfiguredNames = []string{"beta"}
	beta.Headers = map[string]string{"authorization": sharedCredential}

	forward := collapseServerSpecs([]ServerSpec{alpha, beta})
	reverse := collapseServerSpecs([]ServerSpec{beta, alpha})
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("case-insensitive alias collapse depends on input order:\nforward=%+v\nreverse=%+v", forward, reverse)
	}
	if len(forward) != 1 || forward[0].Ambiguity != "" {
		t.Fatalf("equivalent case-variant headers did not collapse: %+v", forward)
	}
	if want := map[string]string{"Authorization": sharedCredential}; !reflect.DeepEqual(forward[0].Headers, want) {
		t.Fatalf("canonical headers = %#v, want %#v", forward[0].Headers, want)
	}

	conflictingAlias := beta
	conflictingAlias.Headers = map[string]string{"authorization": "Basic distinct-value"}
	conflicting := collapseServerSpecs([]ServerSpec{alpha, conflictingAlias})
	if len(conflicting) != 1 || conflicting[0].Ambiguity != ambiguousServerProfileError {
		t.Fatalf("case-variant alias conflict was not rejected: %+v", conflicting)
	}

	conflictingEntry := alpha
	conflictingEntry.Headers = map[string]string{
		"Authorization": "Bearer first-secret",
		"authorization": "Basic second-secret",
	}
	withinEntry := collapseServerSpecs([]ServerSpec{conflictingEntry})
	if len(withinEntry) != 1 || withinEntry[0].Ambiguity != ambiguousServerProfileError {
		t.Fatalf("one-entry canonical header conflict was not rejected: %+v", withinEntry)
	}
}

func TestMCPCollectorRejectsCanonicalHeaderConflictsBeforeNetworkAndDoesNotLeak(t *testing.T) {
	var requests atomic.Int64
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer httpServer.Close()

	for _, test := range []struct {
		name    string
		headers string
	}{
		{
			name: "canonical then lowercase",
			headers: `"Authorization":"Bearer sk-FIRST-CANONICAL-SECRET-123456789",` +
				`"authorization":"Basic sk-SECOND-LOWERCASE-SECRET-123456789"`,
		},
		{
			name: "lowercase then canonical",
			headers: `"authorization":"Basic sk-SECOND-LOWERCASE-SECRET-123456789",` +
				`"Authorization":"Bearer sk-FIRST-CANONICAL-SECRET-123456789"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "claude_desktop_config.json")
			document := fmt.Sprintf(
				`{"mcpServers":{"conflict":{"url":%q,"headers":{%s}}}}`,
				httpServer.URL,
				test.headers,
			)
			if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
				t.Fatalf("write conflicting config: %v", err)
			}

			result, err := NewMCPCollector().Collect(
				context.Background(),
				collector.CollectOptions{
					ConfigPath: configPath,
					ScanID:     "canonical-header-conflict",
				},
			)
			if err != nil {
				t.Fatalf("Collect should preserve a typed failed outcome: %v", err)
			}
			if requests.Load() != 0 {
				t.Fatalf("ambiguous headers reached the network: requests=%d", requests.Load())
			}
			if len(result.Graph.Nodes) != 0 || len(result.Graph.Edges) != 0 {
				t.Fatalf("ambiguous header profile emitted graph facts: %+v", result.Graph)
			}
			if result.Meta.Collection == nil || result.Meta.Collection.State == ingest.OutcomeComplete {
				t.Fatalf("ambiguous header profile reported complete: %+v", result.Meta.Collection)
			}
			serialized, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("marshal failed outcome: %v", err)
			}
			for _, secret := range []string{
				"sk-FIRST-CANONICAL-SECRET-123456789",
				"sk-SECOND-LOWERCASE-SECRET-123456789",
			} {
				if strings.Contains(string(serialized), secret) {
					t.Fatalf("failed outcome leaked %q: %s", secret, serialized)
				}
			}
			if !strings.Contains(string(serialized), ambiguousServerProfileError) {
				t.Fatalf("fixed ambiguity diagnostic missing: %s", serialized)
			}
		})
	}
}

func TestMCPCollectorAmbiguousAliasesDoNotExecuteOrLeak(t *testing.T) {
	tempDir := t.TempDir()
	marker := filepath.Join(tempDir, "must-not-exist")
	configPath := filepath.Join(tempDir, "claude_desktop_config.json")
	configDocument := map[string]any{
		"mcpServers": map[string]any{
			"alpha": map[string]any{
				"command": "/bin/sh",
				"args":    []string{"-c", "touch " + marker},
				"env":     map[string]string{"API_KEY": "sk-AMBIGUOUS-ALPHA-123456789"},
			},
			"beta": map[string]any{
				"command": "/bin/sh",
				"args":    []string{"-c", "touch " + marker},
				"env":     map[string]string{"API_KEY": "sk-AMBIGUOUS-BETA-123456789"},
			},
		},
	}
	encoded, err := json.Marshal(configDocument)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewMCPCollector().Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "ambiguous-aliases",
	})
	if err != nil {
		t.Fatalf("Collect should return a typed failed outcome, got: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("ambiguous profile was executed; marker stat = %v", err)
	}
	if len(result.Graph.Nodes) != 0 || len(result.Graph.Edges) != 0 {
		t.Fatalf("ambiguous access path emitted arbitrary graph facts: %+v", result.Graph)
	}
	if result.Meta.Collection == nil || result.Meta.Collection.State == ingest.OutcomeComplete {
		t.Fatalf("ambiguous collection reported complete: %+v", result.Meta.Collection)
	}
	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, secret := range []string{
		"sk-AMBIGUOUS-ALPHA-123456789", "sk-AMBIGUOUS-BETA-123456789", "touch " + marker,
	} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("ambiguous outcome leaked %q: %s", secret, serialized)
		}
	}
	if !strings.Contains(string(serialized), ambiguousServerProfileError) {
		t.Fatalf("ambiguity diagnostic missing from typed outcome: %s", serialized)
	}
}

func TestMCPCollectorSanitizesLiveHTTPURLSecretsAcrossEntireEnvelope(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "safe-server", Version: "1.0.0"}, nil)
	const userinfoSecret = "sk-RAW-LIVE-USERINFO-SECRET-123456789"
	const querySecret = "sk-RAW-LIVE-QUERY-SECRET-123456789"
	const fragmentSecret = "RAW-LIVE-FRAGMENT-SECRET"
	var requests atomic.Int64
	var standaloneGETs atomic.Int64
	var queryObserved atomic.Bool
	var userinfoObserved atomic.Bool
	httpServer := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			requests.Add(1)
			if request.Method == http.MethodGet {
				standaloneGETs.Add(1)
			}
			if request.URL.Query().Get("api_key") == querySecret {
				queryObserved.Store(true)
			}
			username, password, ok := request.BasicAuth()
			if ok && username == "agenthound-user" && password == userinfoSecret {
				userinfoObserved.Store(true)
			}
			return server
		},
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	))
	defer httpServer.Close()
	rawTarget := fmt.Sprintf(
		"http://agenthound-user:%s@%s?api_key=%s#%s",
		userinfoSecret,
		strings.TrimPrefix(httpServer.URL, "http://"),
		querySecret,
		fragmentSecret,
	)

	result, err := NewMCPCollector().Collect(context.Background(), collector.CollectOptions{
		TargetURL: rawTarget,
		ScanID:    "safe-live-http",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if requests.Load() == 0 || !queryObserved.Load() || !userinfoObserved.Load() {
		t.Fatalf(
			"live request proof failed: requests=%d query=%v userinfo=%v",
			requests.Load(),
			queryObserved.Load(),
			userinfoObserved.Load(),
		)
	}
	if standaloneGETs.Load() != 0 {
		t.Fatalf("collector opened %d optional standalone SSE requests", standaloneGETs.Load())
	}
	if result.Meta.Collection == nil || result.Meta.Collection.State != ingest.OutcomeComplete {
		t.Fatalf("credential-bearing live collection was not complete: %+v", result.Meta.Collection)
	}
	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, forbidden := range []string{
		userinfoSecret,
		querySecret,
		fragmentSecret,
		"agenthound-user",
		"api_key=",
	} {
		if strings.Contains(string(serialized), forbidden) {
			t.Fatalf("live MCP envelope leaked %q: %s", forbidden, serialized)
		}
	}
	servers := make([]ingest.Node, 0)
	for _, node := range result.Graph.Nodes {
		for _, kind := range node.Kinds {
			if kind == "MCPServer" {
				servers = append(servers, node)
				break
			}
		}
	}
	if len(servers) != 1 {
		t.Fatalf("MCPServer nodes = %d, want one", len(servers))
	}
	if got := servers[0].Properties["endpoint"]; got != httpServer.URL {
		t.Fatalf("safe endpoint = %v, want %q", got, httpServer.URL)
	}
	if servers[0].Properties["status"] != "reachable" {
		t.Fatalf("live target was not reachable: %+v", servers[0].Properties)
	}
	if servers[0].Properties["endpoint_userinfo_redacted"] != true ||
		servers[0].Properties["endpoint_query_redacted"] != true ||
		servers[0].Properties["endpoint_fragment_redacted"] != true {
		t.Fatalf("redaction markers missing: %+v", servers[0].Properties)
	}
	if got := servers[0].Properties["observed_auth_method"]; got != string(common.AuthBasic) {
		t.Fatalf("userinfo-backed access auth = %v, want basic", got)
	}
	if got := servers[0].Properties["observed_auth_evidence"]; got != common.AuthEvidenceConfiguredCredential {
		t.Fatalf("userinfo-backed access evidence = %v, want configured credential", got)
	}
}

func TestMCPCoverageKeyUsesCanonicalServerIdentity(t *testing.T) {
	first := ServerSpec{
		Transport: "stdio",
		Command:   "node",
		Args:      []string{"server-a.js"},
	}
	equivalent := first
	second := ServerSpec{
		Transport: "stdio",
		Command:   "node",
		Args:      []string{"server-b.js"},
	}
	if mcpCoverageKey(first) != mcpCoverageKey(equivalent) {
		t.Fatal("equivalent server identities received different coverage keys")
	}
	if mcpCoverageKey(first) == mcpCoverageKey(second) {
		t.Fatal("two targeted MCP servers received the same coverage key")
	}
	httpFirst := ServerSpec{
		Transport: "http",
		URL:       "https://MCP.example:443/api/?b=2&a=1",
	}
	httpEquivalent := ServerSpec{
		Transport: "http",
		URL:       "https://mcp.example/api?a=1&b=2",
	}
	if mcpCoverageKey(httpFirst) != mcpCoverageKey(httpEquivalent) {
		t.Fatal("equivalent HTTP target spellings received different coverage keys")
	}
}

func TestParseConfigForSpecs(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	configJSON := `{
		"mcpServers": {
			"postgres": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres"],
				"env": {
					"POSTGRES_URL": "postgres://localhost/test"
				}
			},
			"remote": {
				"url": "http://localhost:3000/mcp",
				"headers": {
					"Authorization": "Bearer token123"
				}
			},
			"disabled-server": {
				"command": "npx",
				"args": ["-y", "disabled-pkg"],
				"disabled": true
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 2 {
		t.Fatalf("expected 2 specs (disabled excluded), got %d", len(specs))
	}

	foundStdio := false
	foundHTTP := false
	for _, s := range specs {
		if s.Transport == "stdio" && s.Command == "npx" {
			foundStdio = true
			if s.Env["POSTGRES_URL"] != "postgres://localhost/test" {
				t.Error("expected POSTGRES_URL env var")
			}
		}
		if s.Transport == "http" && s.URL == "http://localhost:3000/mcp" {
			foundHTTP = true
			if s.Headers["Authorization"] != "Bearer token123" {
				t.Error("expected Authorization header")
			}
		}
	}

	if !foundStdio {
		t.Error("expected to find stdio server spec")
	}
	if !foundHTTP {
		t.Error("expected to find http server spec")
	}
}

func TestParseConfigForSpecsVSCode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")

	configJSON := `{
		"servers": {
			"my-server": {
				"command": "node",
				"args": ["server.js"]
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}

	if specs[0].Command != "node" {
		t.Errorf("expected command 'node', got %q", specs[0].Command)
	}
}

func TestParseConfigForSpecsVSCodeDottedKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")
	configJSON := `{
		"mcp.servers": {
			"puppeteer": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-puppeteer"]
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].Name != "puppeteer" || specs[0].Command != "npx" {
		t.Fatalf("unexpected spec: %+v", specs[0])
	}
}

func TestParseConfigForSpecsVSCodeNestedMCPServers(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")
	configJSON := `{
		"mcp": {
			"servers": {
				"sqlite": {
					"command": "uvx",
					"args": ["mcp-server-sqlite"]
				}
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].Name != "sqlite" || specs[0].Command != "uvx" {
		t.Fatalf("unexpected spec: %+v", specs[0])
	}
}

func TestParseConfigForSpecsContinueYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := `mcpServers:
  - name: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
    env:
      ROOT: /tmp
  - name: remote
    url: https://example.com/mcp
    headers:
      Authorization: Bearer token
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0].Name != "filesystem" || specs[0].Command != "npx" || specs[0].Env["ROOT"] != "/tmp" {
		t.Fatalf("unexpected first spec: %+v", specs[0])
	}
	if specs[1].Name != "remote" || specs[1].URL != "https://example.com/mcp" ||
		specs[1].Headers["Authorization"] != "Bearer token" {
		t.Fatalf("unexpected second spec: %+v", specs[1])
	}
}

func TestParseConfigForSpecsZed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")

	configJSON := `{
		"context_servers": {
			"my-server": {
				"settings": {
					"command": "python3",
					"args": ["-m", "mcp_server"]
				}
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}

	if specs[0].Command != "python3" {
		t.Errorf("expected command 'python3', got %q", specs[0].Command)
	}
}

func TestParseConfigForSpecsComments(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	configJSON := `{
		// This is a comment
		"mcpServers": {
			"server1": {
				"command": "echo",
				"args": ["hello"]
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
}

func TestParseConfigForSpecsInvalidFile(t *testing.T) {
	specs, err := parseConfigForSpecs("/nonexistent/path.json")
	if err != nil || len(specs) != 0 {
		t.Fatalf("missing explicit path should be complete-empty, got specs=%v err=%v", specs, err)
	}
}

func TestParseConfigForSpecsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "bad.json")

	if err := os.WriteFile(configPath, []byte("not json"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := parseConfigForSpecs(configPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMarshalJSON(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if marshalJSON(nil) != "" {
			t.Error("expected empty string for nil")
		}
	})

	t.Run("map", func(t *testing.T) {
		result := marshalJSON(map[string]any{"type": "object"})
		if result == "" {
			t.Error("expected non-empty JSON string")
		}
	})
}

// claudeDesktopConfigPath returns the per-OS Claude Desktop config path under
// the given home dir, matching modules/config ClaudeDesktopParser.ConfigPaths.
func claudeDesktopConfigPath(homeDir string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "linux":
		return filepath.Join(homeDir, ".config", "Claude", "claude_desktop_config.json")
	case "windows":
		return filepath.Join(homeDir, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	default:
		return ""
	}
}

// TestDiscoverRetainsDistinctStdioServers covers Finding 1: two stdio servers
// sharing the same command but with different args must both survive discovery
// dedup (the old key omitted Args and collapsed them into one).
func TestDiscoverRetainsDistinctStdioServers(t *testing.T) {
	home := t.TempDir()
	dest := claudeDesktopConfigPath(home)
	if dest == "" {
		t.Skip("unsupported OS for discovery path")
	}
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	configJSON := `{
		"mcpServers": {
			"serverA": {"command": "npx", "args": ["-y", "serverA"]},
			"serverB": {"command": "npx", "args": ["-y", "serverB"]}
		}
	}`
	if err := os.WriteFile(dest, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := discoverAllConfigs()
	if err != nil {
		t.Fatalf("discoverAllConfigs: %v", err)
	}

	ids := make(map[string]bool)
	for _, s := range specs {
		ids[computeServerID(s)] = true
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct stdio servers to survive dedup, got %d (specs=%d)", len(ids), len(specs))
	}
}

// TestDiscoverCoversPreviouslyMissedClient covers Finding 18: discovery now
// shares the config collector's parser path registry, so it picks up clients
// the old hardcoded list missed (here: Zed via ~/.config/zed/settings.json).
func TestDiscoverCoversPreviouslyMissedClient(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Zed parser only covers darwin/linux")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	zedPath := filepath.Join(home, ".config", "zed", "settings.json")
	if err := os.MkdirAll(filepath.Dir(zedPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	zedJSON := `{
		"context_servers": {
			"zed-server": {"command": "uvx", "args": ["mcp-server-zed"]}
		}
	}`
	if err := os.WriteFile(zedPath, []byte(zedJSON), 0o644); err != nil {
		t.Fatalf("write zed config: %v", err)
	}

	// Confirm the shared path registry includes the Zed path (the old
	// hardcoded MCP list did not).
	covered := false
	for _, p := range discoveryCandidatePaths(home) {
		if p == zedPath {
			covered = true
			break
		}
	}
	if !covered {
		t.Fatalf("Zed config path %q not in discovery candidates", zedPath)
	}

	specs, err := discoverAllConfigs()
	if err != nil {
		t.Fatalf("discoverAllConfigs: %v", err)
	}
	found := false
	for _, s := range specs {
		if s.Command == "uvx" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected discovery to find the Zed server, but it did not")
	}
}

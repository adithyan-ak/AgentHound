package ingest

import (
	"reflect"
	"sort"
	"testing"
)

func strongTestIdentity(networkHex string) CollectionIdentity {
	return NewCollectionIdentity(
		[]IdentityEvidence{
			testEvidence("os_instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			testEvidence("principal", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		},
		[]IdentityEvidence{testEvidence("network_profile", networkHex)},
		NetworkClassPrivate,
	)
}

func scopingFixture(identity CollectionIdentity, scanID string) *IngestData {
	remoteKey := CanonicalCoverageKey("mcp", "target", "https://service.internal")
	loopbackKey := CanonicalCoverageKey("mcp", "target", "http://127.0.0.1:8080")
	stdioKey := CanonicalCoverageKey("mcp", "target", "stdio-command")
	return &IngestData{
		Meta: IngestMeta{
			ScanID:   scanID,
			Identity: identity,
			Collection: &CollectionReport{
				State:        OutcomeComplete,
				CoverageKeys: []string{remoteKey, loopbackKey, stdioKey},
				Outcomes: []CollectionOutcome{
					{Collector: "mcp", CoverageKey: remoteKey, Target: "https://service.internal", Method: "enumerate", State: OutcomeComplete},
					{Collector: "mcp", CoverageKey: loopbackKey, Target: "http://127.0.0.1:8080", Method: "enumerate", State: OutcomeComplete},
					{Collector: "mcp", CoverageKey: stdioKey, Target: "stdio-command", Method: "enumerate", State: OutcomeComplete},
				},
			},
		},
		Graph: GraphData{
			Nodes: []Node{
				{ID: "file", Kinds: []string{"ConfigFile"}, Properties: map[string]any{"path": "/tmp/config"}, ObservationDomains: []string{stdioKey}},
				{ID: "remote", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "http", "endpoint": "https://service.internal"}, ObservationDomains: []string{remoteKey}},
				{ID: "remote-tool", Kinds: []string{"MCPTool"}, Properties: map[string]any{"name": "remote"}, ObservationDomains: []string{remoteKey}},
				{ID: "loopback", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "http", "endpoint": "http://127.0.0.1:8080"}, ObservationDomains: []string{loopbackKey}},
				{ID: "stdio", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "stdio", "command": "server"}, ObservationDomains: []string{stdioKey}},
				{ID: "credential", Kinds: []string{"Credential"}, Properties: map[string]any{"value_hash": "shared-hash"}, ObservationDomains: []string{stdioKey}},
			},
			Edges: []Edge{{Source: "remote", Target: "remote-tool", Kind: "PROVIDES_TOOL", ObservationDomains: []string{remoteKey}}},
		},
	}
}

func configScopingFixture(identity CollectionIdentity, scanID string) *IngestData {
	pathKey := CanonicalCoverageKey("config", "path", "/tmp/mcp.json")
	rootKey := CollectorRootCoverageKey("config")
	data := &IngestData{
		Meta: IngestMeta{
			ScanID: scanID, Identity: identity,
			Collection: &CollectionReport{
				State:        OutcomeComplete,
				CoverageKeys: []string{pathKey, rootKey},
				AuthoritativeRoots: []CoverageRoot{{
					CoverageKey: rootKey, ChildCoverageKeys: []string{pathKey},
				}},
				Outcomes: []CollectionOutcome{
					{Collector: "config", CoverageKey: pathKey, ParentCoverageKey: rootKey, Target: "/tmp/mcp.json", Method: "config_discovery", State: OutcomeComplete},
					{Collector: "config", CoverageKey: rootKey, Target: "config", Method: "collect", State: OutcomeComplete},
				},
			},
		},
		Graph: GraphData{
			Nodes: []Node{
				{ID: "config-file", Kinds: []string{"ConfigFile"}, Properties: map[string]any{"path": "/tmp/mcp.json"}, ObservationDomains: []string{pathKey}},
				{ID: "agent", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "client"}, ObservationDomains: []string{pathKey}},
				{ID: "server", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "http", "endpoint": "https://service.internal"}, ObservationDomains: []string{pathKey}},
				{ID: "host", Kinds: []string{"Host"}, Properties: map[string]any{"hostname": "service.internal", "scope": "private"}, ObservationDomains: []string{pathKey}},
				{ID: "identity", Kinds: []string{"Identity"}, Properties: map[string]any{"name": "configured"}, ObservationDomains: []string{pathKey}},
				{ID: "credential", Kinds: []string{"Credential"}, Properties: map[string]any{"value_hash": "configured-hash"}, ObservationDomains: []string{pathKey}},
			},
			Edges: []Edge{
				{Source: "agent", Target: "server", Kind: "TRUSTS_SERVER", ObservationDomains: []string{pathKey}},
				{Source: "server", Target: "config-file", Kind: "CONFIGURED_IN", ObservationDomains: []string{pathKey}},
				{Source: "server", Target: "host", Kind: "RUNS_ON", ObservationDomains: []string{pathKey}},
				{Source: "server", Target: "identity", Kind: "AUTHENTICATES_WITH", ObservationDomains: []string{pathKey}},
				{Source: "identity", Target: "credential", Kind: "USES_CREDENTIAL", ObservationDomains: []string{pathKey}},
			},
		},
	}
	return data
}

func unknownNetworkTestIdentity() CollectionIdentity {
	return NewCollectionIdentity(
		[]IdentityEvidence{
			testEvidence("os_instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			testEvidence("principal", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		},
		[]IdentityEvidence{
			testEvidence("network_visibility_unknown", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
			testEvidence("route_private", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
		},
		NetworkClassPrivate,
	)
}

func TestScopeArtifactSeparatesPointNetworkAndLoopbackIdentity(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	data := scopingFixture(identity, "scan-a")
	rawKeys := append([]string(nil), data.Meta.Collection.CoverageKeys...)
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}

	expectedIDs := map[string]string{
		"file":        ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, "file"),
		"remote":      ScopedNodeID(ScopeNetworkContext, identity.NetworkContextID, "remote"),
		"remote-tool": ScopedNodeID(ScopeNetworkContext, identity.NetworkContextID, "remote-tool"),
		"loopback":    ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, "loopback"),
		"stdio":       ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, "stdio"),
		"credential":  ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, "credential"),
	}
	seen := make(map[string]Node)
	for _, node := range data.Graph.Nodes {
		seen[node.ID] = node
	}
	for raw, expected := range expectedIDs {
		if _, present := seen[expected]; !present {
			t.Errorf("%s node missing scoped ID %q", raw, expected)
		}
	}
	remote := seen[expectedIDs["remote"]]
	if remote.Properties["collection_point_id"] != identity.CollectionPointID ||
		remote.Properties["network_context_id"] != identity.NetworkContextID {
		t.Fatalf("remote scope coordinates = %+v", remote.Properties)
	}
	if seen[expectedIDs["credential"]].Properties["value_hash"] != "shared-hash" {
		t.Fatal("credential correlation hash changed during scoping")
	}

	wantCoverage := []string{
		ScopedCoverageKey(ScopeNetworkContext, identity.NetworkContextID, rawKeys[0]),
		ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, rawKeys[1]),
		ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, rawKeys[2]),
	}
	sort.Strings(wantCoverage)
	if !reflect.DeepEqual(data.Meta.Collection.CoverageKeys, wantCoverage) {
		t.Fatalf("coverage = %v, want %v", data.Meta.Collection.CoverageKeys, wantCoverage)
	}
}

func TestScopeArtifactNetworkMovePreservesOnlyPointScopedIdentity(t *testing.T) {
	firstIdentity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	secondIdentity := strongTestIdentity("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	first := scopingFixture(firstIdentity, "scan-a")
	second := scopingFixture(secondIdentity, "scan-b")
	if err := ScopeArtifact(first); err != nil {
		t.Fatal(err)
	}
	if err := ScopeArtifact(second); err != nil {
		t.Fatal(err)
	}
	ids := func(data *IngestData) map[string]string {
		result := make(map[string]string)
		for _, node := range data.Graph.Nodes {
			if name, ok := node.Properties["name"].(string); ok {
				result[name] = node.ID
			}
			if valueHash, ok := node.Properties["value_hash"].(string); ok {
				result[valueHash] = node.ID
			}
			if transport, ok := node.Properties["transport"].(string); ok {
				if endpoint, endpointOK := node.Properties["endpoint"].(string); endpointOK {
					result[endpoint] = node.ID
				} else {
					result[transport] = node.ID
				}
			}
		}
		return result
	}
	firstIDs, secondIDs := ids(first), ids(second)
	for _, stable := range []string{"http://127.0.0.1:8080", "stdio", "shared-hash"} {
		if firstIDs[stable] != secondIDs[stable] {
			t.Errorf("point-scoped %s changed across network contexts", stable)
		}
	}
	for _, changed := range []string{"https://service.internal", "remote"} {
		if firstIDs[changed] == secondIDs[changed] {
			t.Errorf("network-scoped %s merged across network contexts", changed)
		}
	}
}

func TestScopeArtifactSeparatesRemoteIdentityAndCredentialAcrossNetworks(t *testing.T) {
	firstIdentity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	secondIdentity := strongTestIdentity("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	fixture := func(identity CollectionIdentity, scanID string) *IngestData {
		a2aKey := CanonicalCoverageKey("a2a", "target", "https://agent.internal")
		lootKey := CanonicalCoverageKey("scan", "loot", "litellm\x00https://service.internal")
		return &IngestData{
			Meta: IngestMeta{
				ScanID: scanID, Identity: identity, Extra: map[string]any{"loot_type": "litellm"},
				Collection: &CollectionReport{
					State: OutcomeComplete, CoverageKeys: []string{a2aKey, lootKey},
					Outcomes: []CollectionOutcome{
						{Collector: "a2a", CoverageKey: a2aKey, Target: "https://agent.internal", Method: "agent_card", State: OutcomeComplete},
						{Collector: "scan", CoverageKey: lootKey, Target: "https://service.internal", Method: "loot:litellm", State: OutcomeComplete},
					},
				},
			},
			Graph: GraphData{
				Nodes: []Node{
					{ID: "agent", Kinds: []string{"A2AAgent"}, Properties: map[string]any{"url": "https://agent.internal"}, ObservationDomains: []string{a2aKey}},
					{ID: "remote-identity", Kinds: []string{"Identity"}, Properties: map[string]any{"type": "apiKey"}, ObservationDomains: []string{a2aKey}},
					{ID: "gateway", Kinds: []string{"LiteLLMGateway", "AIService"}, Properties: map[string]any{"endpoint": "https://service.internal"}, ObservationDomains: []string{lootKey}},
					{ID: "remote-credential", Kinds: []string{"Credential"}, Properties: map[string]any{"value_hash": "shared-secret-hash", "merge_key": "value_hash"}, ObservationDomains: []string{lootKey}},
				},
				Edges: []Edge{
					{Source: "agent", Target: "remote-identity", Kind: "AUTHENTICATES_WITH", ObservationDomains: []string{a2aKey}},
					{Source: "gateway", Target: "remote-credential", Kind: "EXPOSES_CREDENTIAL", ObservationDomains: []string{lootKey}},
				},
			},
		}
	}

	first := fixture(firstIdentity, "remote-children-a")
	second := fixture(secondIdentity, "remote-children-b")
	if err := ScopeArtifact(first); err != nil {
		t.Fatal(err)
	}
	if err := ScopeArtifact(second); err != nil {
		t.Fatal(err)
	}

	for _, rawID := range []string{"remote-identity", "remote-credential"} {
		firstID := ScopedNodeID(ScopeNetworkContext, firstIdentity.NetworkContextID, rawID)
		secondID := ScopedNodeID(ScopeNetworkContext, secondIdentity.NetworkContextID, rawID)
		if firstID == secondID || !hasNodeID(first.Graph.Nodes, firstID) || !hasNodeID(second.Graph.Nodes, secondID) {
			t.Fatalf("remote child %q did not separate by network: first=%q second=%q", rawID, firstID, secondID)
		}
	}
	for _, data := range []*IngestData{first, second} {
		for _, node := range data.Graph.Nodes {
			if node.Properties["value_hash"] == "shared-secret-hash" &&
				node.Properties["merge_key"] != "value_hash" {
				t.Fatalf("credential correlation primitive changed: %+v", node)
			}
		}
	}
}

func TestScopeArtifactRemoteChildrenInheritTopologyWithoutDomains(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	data := &IngestData{
		Meta: IngestMeta{ScanID: "topology-children", Identity: identity, Collection: &CollectionReport{}},
		Graph: GraphData{
			Nodes: []Node{
				{ID: "agent", Kinds: []string{"A2AAgent"}, Properties: map[string]any{"url": "https://agent.internal"}},
				{ID: "identity", Kinds: []string{"Identity"}, Properties: map[string]any{"type": "apiKey"}},
				{ID: "credential", Kinds: []string{"Credential"}, Properties: map[string]any{"value_hash": "hash"}},
			},
			Edges: []Edge{
				{Source: "agent", Target: "identity", Kind: "AUTHENTICATES_WITH"},
				{Source: "identity", Target: "credential", Kind: "USES_CREDENTIAL"},
			},
		},
	}
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}
	for _, rawID := range []string{"identity", "credential"} {
		want := ScopedNodeID(ScopeNetworkContext, identity.NetworkContextID, rawID)
		if !hasNodeID(data.Graph.Nodes, want) {
			t.Fatalf("topology child %q missing network-scoped ID %q", rawID, want)
		}
	}
}

func TestScopeArtifactEndpointChildrenPreferOwningTopologyOverBroadCoverage(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	coverageKey := CanonicalCoverageKey("mcp", "inventory", "mixed-services")
	data := &IngestData{
		Meta: IngestMeta{
			ScanID: "mixed-service-children", Identity: identity,
			Collection: &CollectionReport{
				State: OutcomeComplete, CoverageKeys: []string{coverageKey},
				Outcomes: []CollectionOutcome{{
					Collector: "mcp", CoverageKey: coverageKey, Target: "mixed-services",
					Method: "enumerate", State: OutcomeComplete,
				}},
			},
		},
		Graph: GraphData{
			Nodes: []Node{
				{ID: "remote", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "http", "endpoint": "https://service.internal"}, ObservationDomains: []string{coverageKey}},
				{ID: "local", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "http", "endpoint": "http://127.0.0.1:8080"}, ObservationDomains: []string{coverageKey}},
				{ID: "remote-identity", Kinds: []string{"Identity"}, Properties: map[string]any{"name": "remote"}, ObservationDomains: []string{coverageKey}},
				{ID: "local-identity", Kinds: []string{"Identity"}, Properties: map[string]any{"name": "local"}, ObservationDomains: []string{coverageKey}},
				{ID: "remote-credential", Kinds: []string{"Credential"}, Properties: map[string]any{"value_hash": "remote-hash"}, ObservationDomains: []string{coverageKey}},
				{ID: "local-credential", Kinds: []string{"Credential"}, Properties: map[string]any{"value_hash": "local-hash"}, ObservationDomains: []string{coverageKey}},
			},
			Edges: []Edge{
				{Source: "remote", Target: "remote-identity", Kind: "AUTHENTICATES_WITH", ObservationDomains: []string{coverageKey}},
				{Source: "remote-identity", Target: "remote-credential", Kind: "USES_CREDENTIAL", ObservationDomains: []string{coverageKey}},
				{Source: "local", Target: "local-identity", Kind: "AUTHENTICATES_WITH", ObservationDomains: []string{coverageKey}},
				{Source: "local-identity", Target: "local-credential", Kind: "USES_CREDENTIAL", ObservationDomains: []string{coverageKey}},
			},
		},
	}
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}
	for _, rawID := range []string{"remote-identity", "remote-credential"} {
		want := ScopedNodeID(ScopeNetworkContext, identity.NetworkContextID, rawID)
		if !hasNodeID(data.Graph.Nodes, want) {
			t.Fatalf("remote child %q missing owning network scope %q", rawID, want)
		}
	}
	for _, rawID := range []string{"local-identity", "local-credential"} {
		want := ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, rawID)
		if !hasNodeID(data.Graph.Nodes, want) {
			t.Fatalf("local child %q missing owning point scope %q", rawID, want)
		}
	}
}

func TestScopeArtifactConfigCredentialRemainsPointScopedForRemoteService(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	coverageKey := CanonicalCoverageKey("config", "path", "/tmp/mcp.json")
	data := &IngestData{
		Meta: IngestMeta{
			ScanID: "config-credential", Identity: identity,
			Collection: &CollectionReport{State: OutcomeComplete, CoverageKeys: []string{coverageKey}},
		},
		Graph: GraphData{
			Nodes: []Node{
				{ID: "server", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "http", "endpoint": "https://service.internal"}, ObservationDomains: []string{coverageKey}},
				{ID: "identity", Kinds: []string{"Identity"}, Properties: map[string]any{"name": "configured"}, ObservationDomains: []string{coverageKey}},
				{ID: "credential", Kinds: []string{"Credential"}, Properties: map[string]any{"value_hash": "configured-hash"}, ObservationDomains: []string{coverageKey}},
			},
			Edges: []Edge{
				{Source: "server", Target: "identity", Kind: "AUTHENTICATES_WITH", ObservationDomains: []string{coverageKey}},
				{Source: "identity", Target: "credential", Kind: "USES_CREDENTIAL", ObservationDomains: []string{coverageKey}},
			},
		},
	}
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}
	for _, rawID := range []string{"identity", "credential"} {
		want := ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, rawID)
		if !hasNodeID(data.Graph.Nodes, want) {
			t.Fatalf("configured child %q missing point scope %q", rawID, want)
		}
	}
}

func TestScopeArtifactConfigRemoteCoverageCoexistsAcrossNetworks(t *testing.T) {
	firstIdentity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	secondIdentity := strongTestIdentity("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	first := configScopingFixture(firstIdentity, "config-network-a")
	second := configScopingFixture(secondIdentity, "config-network-b")
	if err := ScopeArtifact(first); err != nil {
		t.Fatal(err)
	}
	if err := ScopeArtifact(second); err != nil {
		t.Fatal(err)
	}

	firstRemoteDomain := onlyNodeDomain(t, first, ScopedNodeID(ScopeNetworkContext, firstIdentity.NetworkContextID, "server"))
	secondRemoteDomain := onlyNodeDomain(t, second, ScopedNodeID(ScopeNetworkContext, secondIdentity.NetworkContextID, "server"))
	if firstRemoteDomain == secondRemoteDomain {
		t.Fatalf("remote config coverage collapsed across networks: %q", firstRemoteDomain)
	}
	if containsString(CompleteCoverageDomains(second.Meta.Collection), firstRemoteDomain) {
		t.Fatalf("network B complete domains would retire network A: %q", firstRemoteDomain)
	}
	pathKey := CanonicalCoverageKey("config", "path", "/tmp/mcp.json")
	rootKey := CollectorRootCoverageKey("config")
	pointRoot := ScopedCoverageKey(ScopeCollectionPoint, firstIdentity.CollectionPointID, rootKey)
	networkRoot := ScopedCoverageKey(ScopeNetworkContext, firstIdentity.NetworkContextID, rootKey)
	pointChild := ScopedCoverageKey(ScopeCollectionPoint, firstIdentity.CollectionPointID, pathKey)
	wantRoots := []CoverageRoot{
		{CoverageKey: pointRoot, ChildCoverageKeys: []string{pointChild}},
		{CoverageKey: networkRoot, ChildCoverageKeys: []string{firstRemoteDomain}},
	}
	sort.Slice(wantRoots, func(i, j int) bool { return wantRoots[i].CoverageKey < wantRoots[j].CoverageKey })
	if !reflect.DeepEqual(first.Meta.Collection.AuthoritativeRoots, wantRoots) {
		t.Fatalf("split config roots = %+v, want %+v", first.Meta.Collection.AuthoritativeRoots, wantRoots)
	}
	for _, edge := range first.Graph.Edges[:4] {
		if len(edge.ObservationDomains) != 1 || edge.ObservationDomains[0] != firstRemoteDomain {
			t.Fatalf("remote config topology kept cross-context ownership: %+v", edge)
		}
	}
}

func TestScopeArtifactUnknownNetworkConfigRemainsAdditive(t *testing.T) {
	identity := unknownNetworkTestIdentity()
	first := configScopingFixture(identity, "unknown-config-a")
	second := configScopingFixture(identity, "unknown-config-b")
	if err := ScopeArtifact(first); err != nil {
		t.Fatal(err)
	}
	if err := ScopeArtifact(second); err != nil {
		t.Fatal(err)
	}

	firstArtifactID := framedSHA256("agenthound-artifact-scope-v1", first.Meta.ScanID)
	secondArtifactID := framedSHA256("agenthound-artifact-scope-v1", second.Meta.ScanID)
	firstDomain := onlyNodeDomain(t, first, ScopedNodeID(ScopeArtifactLocal, firstArtifactID, "server"))
	secondDomain := onlyNodeDomain(t, second, ScopedNodeID(ScopeArtifactLocal, secondArtifactID, "server"))
	if firstDomain == secondDomain || containsString(CompleteCoverageDomains(second.Meta.Collection), firstDomain) {
		t.Fatalf("unknown-network config was not additive: first=%q second=%q", firstDomain, secondDomain)
	}
	rootKey := CollectorRootCoverageKey("config")
	firstArtifactRoot := ScopedCoverageKey(ScopeArtifactLocal, firstArtifactID, rootKey)
	secondArtifactRoot := ScopedCoverageKey(ScopeArtifactLocal, secondArtifactID, rootKey)
	if firstArtifactRoot == secondArtifactRoot ||
		CoverageParents(first.Meta.Collection)[firstDomain] != firstArtifactRoot ||
		CoverageParents(second.Meta.Collection)[secondDomain] != secondArtifactRoot {
		t.Fatalf("unknown-network config roots crossed artifacts: first=%+v second=%+v", first.Meta.Collection.AuthoritativeRoots, second.Meta.Collection.AuthoritativeRoots)
	}
}

func TestScopeArtifactConfigPointFactsStillReconcileAcrossNetworks(t *testing.T) {
	firstIdentity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	secondIdentity := strongTestIdentity("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	first := configScopingFixture(firstIdentity, "config-point-a")
	second := configScopingFixture(secondIdentity, "config-point-b")
	if err := ScopeArtifact(first); err != nil {
		t.Fatal(err)
	}
	if err := ScopeArtifact(second); err != nil {
		t.Fatal(err)
	}

	pointID := ScopedNodeID(ScopeCollectionPoint, firstIdentity.CollectionPointID, "config-file")
	firstDomain := onlyNodeDomain(t, first, pointID)
	secondDomain := onlyNodeDomain(t, second, pointID)
	if firstDomain != secondDomain || !containsString(CompleteCoverageDomains(second.Meta.Collection), firstDomain) {
		t.Fatalf("point config facts stopped reconciling: first=%q second=%q complete=%v", firstDomain, secondDomain, CompleteCoverageDomains(second.Meta.Collection))
	}
	uses := second.Graph.Edges[4]
	if len(uses.ObservationDomains) != 1 || uses.ObservationDomains[0] != secondDomain {
		t.Fatalf("point credential topology left point coverage: %+v", uses)
	}
}

func onlyNodeDomain(t *testing.T, data *IngestData, id string) string {
	t.Helper()
	for _, node := range data.Graph.Nodes {
		if node.ID != id {
			continue
		}
		if len(node.ObservationDomains) != 1 {
			t.Fatalf("node %q domains = %v, want one", id, node.ObservationDomains)
		}
		return node.ObservationDomains[0]
	}
	t.Fatalf("node %q not found", id)
	return ""
}

func hasNodeID(nodes []Node, id string) bool {
	for _, node := range nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}

func TestScopeArtifactUnknownNetworkIsolatesOnlyNetworkEvidence(t *testing.T) {
	identity := NewCollectionIdentity(
		[]IdentityEvidence{
			testEvidence("os_instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			testEvidence("principal", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		},
		[]IdentityEvidence{
			testEvidence("network_visibility_unknown", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
			testEvidence("route_private", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
		},
		NetworkClassPrivate,
	)
	first := scopingFixture(identity, "unknown-network-a")
	second := scopingFixture(identity, "unknown-network-b")
	if err := ScopeArtifact(first); err != nil {
		t.Fatal(err)
	}
	if err := ScopeArtifact(second); err != nil {
		t.Fatal(err)
	}

	pointID := ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, "file")
	if first.Graph.Nodes[0].ID != pointID || second.Graph.Nodes[0].ID != pointID {
		t.Fatal("unknown network weakened collection-point evidence")
	}
	if first.Graph.Nodes[1].ID == second.Graph.Nodes[1].ID {
		t.Fatal("unknown network merged remote evidence across artifacts")
	}
	for _, data := range []*IngestData{first, second} {
		remote := data.Graph.Nodes[1]
		if remote.Properties["artifact_scope_id"] == nil || remote.Properties["network_context_id"] != nil {
			t.Fatalf("remote evidence did not receive artifact-local network scope: %+v", remote.Properties)
		}
	}
}

func TestScopeArtifactWeakIdentityIsArtifactLocal(t *testing.T) {
	weak := NewCollectionIdentity(
		[]IdentityEvidence{testEvidence("hostname", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")},
		[]IdentityEvidence{testEvidence("offline", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")},
		NetworkClassOffline,
	)
	first := scopingFixture(weak, "weak-scan-a")
	second := scopingFixture(weak, "weak-scan-b")
	rawCoverage := first.Meta.Collection.CoverageKeys[0]
	if err := ScopeArtifact(first); err != nil {
		t.Fatal(err)
	}
	if err := ScopeArtifact(second); err != nil {
		t.Fatal(err)
	}
	if first.Graph.Nodes[1].ID == second.Graph.Nodes[1].ID {
		t.Fatal("weak artifacts merged an authoritative node")
	}
	firstArtifactScope := framedSHA256("agenthound-artifact-scope-v1", "weak-scan-a")
	if first.Meta.Collection.CoverageKeys[0] == rawCoverage ||
		first.Graph.Nodes[1].Properties["artifact_scope_id"] != firstArtifactScope {
		t.Fatalf("weak artifact did not receive artifact-local scope: %+v", first.Graph.Nodes[1])
	}
}

func TestScopeArtifactWeakIdentityLocalizesReferencesAndTheirEdges(t *testing.T) {
	weak := NewCollectionIdentity(
		[]IdentityEvidence{testEvidence("hostname", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")},
		[]IdentityEvidence{testEvidence("offline", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")},
		NetworkClassOffline,
	)
	data := &IngestData{
		Meta: IngestMeta{ScanID: "weak-reference", Identity: weak, Collection: &CollectionReport{}},
		Graph: GraphData{
			Nodes: []Node{
				{ID: "known-agent", Kinds: []string{"AgentInstance"}, Properties: map[string]any{}, PropertySemantics: NodePropertySemanticsReferenceOnly},
				{ID: "known-resource", Kinds: []string{"MCPResource"}, Properties: map[string]any{}, PropertySemantics: NodePropertySemanticsReferenceOnly},
			},
			Edges: []Edge{{Source: "known-agent", Target: "known-resource", Kind: "CREDENTIAL_REACH_VERIFIED"}},
		},
	}
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}
	artifactID := framedSHA256("agenthound-artifact-scope-v1", data.Meta.ScanID)
	wantAgent := ScopedNodeID(ScopeArtifactLocal, artifactID, "known-agent")
	wantResource := ScopedNodeID(ScopeArtifactLocal, artifactID, "known-resource")
	if data.Graph.Nodes[0].ID != wantAgent || data.Graph.Nodes[1].ID != wantResource {
		t.Fatalf("weak references escaped artifact scope: %+v", data.Graph.Nodes)
	}
	if data.Graph.Edges[0].Source != wantAgent || data.Graph.Edges[0].Target != wantResource {
		t.Fatalf("weak reference edge escaped artifact scope: %+v", data.Graph.Edges[0])
	}
}

func TestScopeArtifactPreservesReferenceOnlySemantics(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	data := &IngestData{
		Meta: IngestMeta{ScanID: "reference-scan", Identity: identity, Collection: &CollectionReport{}},
		Graph: GraphData{
			Nodes: []Node{
				{ID: "server", Kinds: []string{"MCPServer"}, Properties: map[string]any{"transport": "http", "endpoint": "https://service.internal"}},
				{ID: "server", Kinds: []string{"MCPServer"}, Properties: map[string]any{}, PropertySemantics: NodePropertySemanticsReferenceOnly},
				{ID: "external-model", Kinds: []string{"Model"}, Properties: map[string]any{}, PropertySemantics: NodePropertySemanticsReferenceOnly},
				{ID: "signal", Kinds: []string{"ExtractedTrainingSignal"}, Properties: map[string]any{"source_model_id": "external-model"}},
			},
			Edges: []Edge{{Source: "external-model", Target: "signal", Kind: "EXTRACTED_FROM"}},
		},
	}
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}
	scopedServer := ScopedNodeID(ScopeNetworkContext, identity.NetworkContextID, "server")
	if data.Graph.Nodes[1].ID != scopedServer || len(data.Graph.Nodes[1].Properties) != 0 {
		t.Fatalf("reference contribution gained properties or wrong ID: %+v", data.Graph.Nodes[1])
	}
	if data.Graph.Nodes[2].ID != "external-model" {
		t.Fatalf("unresolved reference identity changed: %+v", data.Graph.Nodes[2])
	}
	wantSignal := ScopedNodeID(ScopeReference, "external-model", "signal")
	if data.Graph.Nodes[3].ID != wantSignal || data.Graph.Edges[0].Target != wantSignal {
		t.Fatalf("reference-derived child scope = node %q edge target %q, want %q", data.Graph.Nodes[3].ID, data.Graph.Edges[0].Target, wantSignal)
	}
}

func TestScopeArtifactScopesStandaloneServiceReferenceByCoverage(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	coverageKey := CanonicalCoverageKey("scan", "loot", "http://127.0.0.1:4000")
	data := &IngestData{
		Meta: IngestMeta{
			ScanID:   "loot-reference",
			Identity: identity,
			Extra:    map[string]any{"loot_type": "litellm"},
			Collection: &CollectionReport{
				State:        OutcomeComplete,
				CoverageKeys: []string{coverageKey},
				Outcomes: []CollectionOutcome{{
					Collector: "scan", CoverageKey: coverageKey,
					Target: "127.0.0.1:4000", Method: "loot:litellm", State: OutcomeComplete,
				}},
			},
		},
		Graph: GraphData{Nodes: []Node{{
			ID: "gateway", Kinds: []string{"LiteLLMGateway"}, Properties: map[string]any{},
			ObservationDomains: []string{coverageKey}, PropertySemantics: NodePropertySemanticsReferenceOnly,
		}}},
	}
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}
	wantID := ScopedNodeID(ScopeCollectionPoint, identity.CollectionPointID, "gateway")
	if data.Graph.Nodes[0].ID != wantID || len(data.Graph.Nodes[0].Properties) != 0 {
		t.Fatalf("standalone reference = %+v, want point-scoped empty reference %q", data.Graph.Nodes[0], wantID)
	}
}

func TestScopeArtifactPreservesPreScopedCampaignReferences(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	coverageKey := CanonicalCoverageKey("scan", "campaign", "campaign-proof")
	data := &IngestData{
		Meta: IngestMeta{
			ScanID:   "campaign-reference",
			Identity: identity,
			Extra:    map[string]any{"campaign_artifact": map[string]any{}},
			Collection: &CollectionReport{
				State:        OutcomeComplete,
				CoverageKeys: []string{coverageKey},
				Outcomes: []CollectionOutcome{{
					Collector: "scan", CoverageKey: coverageKey,
					Target: "sha256:scoped-resource", Method: "campaign:cred-reach", State: OutcomeComplete,
				}},
			},
		},
		Graph: GraphData{Nodes: []Node{{
			ID: "sha256:already-scoped", Kinds: []string{"MCPResource"}, Properties: map[string]any{},
			ObservationDomains: []string{coverageKey}, PropertySemantics: NodePropertySemanticsReferenceOnly,
		}}},
	}
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}
	if data.Graph.Nodes[0].ID != "sha256:already-scoped" {
		t.Fatalf("campaign reference was scoped twice: %+v", data.Graph.Nodes[0])
	}
}

func TestScopeArtifactSplitsMCPRootByExplicitChildScope(t *testing.T) {
	identity := strongTestIdentity("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	data := scopingFixture(identity, "root-scan")
	remoteKey := data.Meta.Collection.CoverageKeys[0]
	loopbackKey := data.Meta.Collection.CoverageKeys[1]
	stdioKey := data.Meta.Collection.CoverageKeys[2]
	root := CollectorRootCoverageKey("mcp")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, CollectionOutcome{
		Collector: "mcp", CoverageKey: root, Target: "mcp", Method: "collect", State: OutcomeComplete,
	})
	data.Meta.Collection.AuthoritativeRoots = []CoverageRoot{{CoverageKey: root, ChildCoverageKeys: []string{remoteKey, loopbackKey, stdioKey}}}
	EnsureCoverageParentage(data.Meta.Collection)
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}

	pointRoot := ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, root)
	networkRoot := ScopedCoverageKey(ScopeNetworkContext, identity.NetworkContextID, root)
	pointChild := ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, stdioKey)
	loopbackChild := ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, loopbackKey)
	networkChild := ScopedCoverageKey(ScopeNetworkContext, identity.NetworkContextID, remoteKey)
	pointChildren := []string{pointChild, loopbackChild}
	sort.Strings(pointChildren)
	wantRoots := []CoverageRoot{
		{CoverageKey: pointRoot, ChildCoverageKeys: pointChildren},
		{CoverageKey: networkRoot, ChildCoverageKeys: []string{networkChild}},
	}
	sort.Slice(wantRoots, func(i, j int) bool { return wantRoots[i].CoverageKey < wantRoots[j].CoverageKey })
	if !reflect.DeepEqual(data.Meta.Collection.AuthoritativeRoots, wantRoots) {
		t.Fatalf("roots = %+v, want %+v", data.Meta.Collection.AuthoritativeRoots, wantRoots)
	}
	parents := CoverageParents(data.Meta.Collection)
	if parents[pointChild] != pointRoot || parents[loopbackChild] != pointRoot || parents[networkChild] != networkRoot {
		t.Fatalf("explicit scoped parentage = %+v", parents)
	}
}

func TestScopeArtifactUnknownNetworkSplitsMCPRootBetweenPointAndArtifact(t *testing.T) {
	identity := NewCollectionIdentity(
		[]IdentityEvidence{
			testEvidence("os_instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			testEvidence("principal", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		},
		[]IdentityEvidence{
			testEvidence("network_visibility_unknown", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
			testEvidence("route_private", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
		},
		NetworkClassPrivate,
	)
	data := scopingFixture(identity, "unknown-root-scan")
	remoteKey := data.Meta.Collection.CoverageKeys[0]
	loopbackKey := data.Meta.Collection.CoverageKeys[1]
	stdioKey := data.Meta.Collection.CoverageKeys[2]
	root := CollectorRootCoverageKey("mcp")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, CollectionOutcome{
		Collector: "mcp", CoverageKey: root, Target: "mcp", Method: "collect", State: OutcomeComplete,
	})
	data.Meta.Collection.AuthoritativeRoots = []CoverageRoot{{CoverageKey: root, ChildCoverageKeys: []string{remoteKey, loopbackKey, stdioKey}}}
	EnsureCoverageParentage(data.Meta.Collection)
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}

	artifactID := framedSHA256("agenthound-artifact-scope-v1", data.Meta.ScanID)
	pointRoot := ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, root)
	artifactRoot := ScopedCoverageKey(ScopeArtifactLocal, artifactID, root)
	if len(data.Meta.Collection.AuthoritativeRoots) != 2 {
		t.Fatalf("roots = %+v, want point and artifact roots", data.Meta.Collection.AuthoritativeRoots)
	}
	parents := CoverageParents(data.Meta.Collection)
	if parents[ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, loopbackKey)] != pointRoot ||
		parents[ScopedCoverageKey(ScopeCollectionPoint, identity.CollectionPointID, stdioKey)] != pointRoot ||
		parents[ScopedCoverageKey(ScopeArtifactLocal, artifactID, remoteKey)] != artifactRoot {
		t.Fatalf("unknown-network scoped parentage = %+v", parents)
	}
}

func TestScopeArtifactWeakIdentityKeepsMCPRootArtifactLocal(t *testing.T) {
	identity := NewCollectionIdentity(
		[]IdentityEvidence{testEvidence("hostname", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		[]IdentityEvidence{testEvidence("route_private", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
		NetworkClassPrivate,
	)
	data := scopingFixture(identity, "weak-root-scan")
	children := append([]string(nil), data.Meta.Collection.CoverageKeys...)
	root := CollectorRootCoverageKey("mcp")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, CollectionOutcome{
		Collector: "mcp", CoverageKey: root, Target: "mcp", Method: "collect", State: OutcomeComplete,
	})
	data.Meta.Collection.AuthoritativeRoots = []CoverageRoot{{CoverageKey: root, ChildCoverageKeys: children}}
	EnsureCoverageParentage(data.Meta.Collection)
	if err := ScopeArtifact(data); err != nil {
		t.Fatal(err)
	}

	artifactID := framedSHA256("agenthound-artifact-scope-v1", data.Meta.ScanID)
	artifactRoot := ScopedCoverageKey(ScopeArtifactLocal, artifactID, root)
	if len(data.Meta.Collection.AuthoritativeRoots) != 1 ||
		data.Meta.Collection.AuthoritativeRoots[0].CoverageKey != artifactRoot {
		t.Fatalf("weak roots = %+v, want artifact-local root", data.Meta.Collection.AuthoritativeRoots)
	}
	for _, child := range children {
		scopedChild := ScopedCoverageKey(ScopeArtifactLocal, artifactID, child)
		if CoverageParents(data.Meta.Collection)[scopedChild] != artifactRoot {
			t.Fatalf("weak child %q escaped artifact root", child)
		}
	}
}

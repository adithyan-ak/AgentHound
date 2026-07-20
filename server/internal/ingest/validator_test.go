package ingest

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	collectorcli "github.com/adithyan-ak/agenthound/collector/cli"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

var testCollectionOrigin = ingest.CollectionOrigin{
	HostID:         "agenthound-test-workstation",
	NetworkRealmID: "agenthound-test-lab",
}

func validIngestData() *ingest.IngestData {
	scope := ingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	return &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          ingest.CurrentVersion,
			Type:             ingest.IngestType,
			Origin:           testCollectionOrigin,
			Collector:        "mcp",
			CollectorVersion: "0.1.0",
			Timestamp:        "2026-04-06T10:30:00Z",
			ScanID:           "scan-001",
			Collection: &ingest.CollectionReport{
				State:        ingest.OutcomeComplete,
				CoverageKeys: []string{scope},
				Outcomes: []ingest.CollectionOutcome{{
					Collector:   "mcp",
					CoverageKey: scope,
					Target:      "https://mcp.example",
					Method:      "enumerate",
					State:       ingest.OutcomeComplete,
					Items:       2,
				}},
			},
			Ruleset:         ingest.EmptyRulesetManifest(),
			IdentitySchemes: ingest.CurrentIdentitySchemes(),
		},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{
				{
					ID: "sha256:aaa", Kinds: []string{"MCPServer"},
					Properties: map[string]any{
						"name": "srv", "auth_method": "unknown",
						"auth_assurance": "unknown", "auth_evidence": "unknown",
					},
					ObservationDomains: []string{scope},
				},
				{
					ID: "sha256:bbb", Kinds: []string{"MCPTool"},
					Properties:         map[string]any{"name": "tool"},
					ObservationDomains: []string{scope},
				},
			},
			Edges: []ingest.Edge{
				{
					Source: "sha256:aaa", Target: "sha256:bbb",
					Kind: "PROVIDES_TOOL", SourceKind: "MCPServer", TargetKind: "MCPTool",
					Properties:         map[string]any{"risk_weight": 0.1},
					ObservationDomains: []string{scope},
				},
			},
		},
	}
}

func TestValidatorAcceptsValid(t *testing.T) {
	v := NewValidator()
	if err := v.Validate(validIngestData()); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidatorRejectsNoncanonicalCollectionOrigin(t *testing.T) {
	tests := []struct {
		name     string
		origin   ingest.CollectionOrigin
		wantPath string
	}{
		{
			name:     "missing host",
			origin:   ingest.CollectionOrigin{NetworkRealmID: "realm-a"},
			wantPath: "meta.origin.host_id",
		},
		{
			name:     "missing realm",
			origin:   ingest.CollectionOrigin{HostID: "host-a"},
			wantPath: "meta.origin.network_realm_id",
		},
		{
			name:     "uppercase host",
			origin:   ingest.CollectionOrigin{HostID: "Host-a", NetworkRealmID: "realm-a"},
			wantPath: "meta.origin.host_id",
		},
		{
			name:     "whitespace realm",
			origin:   ingest.CollectionOrigin{HostID: "host-a", NetworkRealmID: "realm-a "},
			wantPath: "meta.origin.network_realm_id",
		},
		{
			name: "oversized host",
			origin: ingest.CollectionOrigin{
				HostID:         strings.Repeat("a", ingest.MaxOriginIDLength+1),
				NetworkRealmID: "realm-a",
			},
			wantPath: "meta.origin.host_id",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			data.Meta.Origin = test.origin
			assertValidationError(t, NewValidator().Validate(data), test.wantPath)
		})
	}
}

// campaignEvidenceIngest builds a "scan"-collector envelope carrying a
// CREDENTIAL_REACH_VERIFIED edge with both reference_only endpoint nodes, exactly
// as the campaign runner emits it.
func campaignEvidenceIngest() *ingest.IngestData {
	serverID := "sha256:camp-srv"
	uri := "postgres://prod/customers"
	resID := ingest.ComputeNodeID("MCPResource", serverID, uri)
	credID := "sha256:camp-cred"
	agentID := "sha256:camp-agent"
	ev := campaign.Evidence{
		ScenarioID: "cred-reach", ScenarioVersion: 1, RunID: "run-1",
		EngagementID: "ENG", OracleType: campaign.OracleTypeDifferentialCredentialReach,
		Outcome:      campaign.OutcomeCredentialGatedReachVerified,
		ControlStage: campaign.ProbeStageResourceRead, ControlStatus: campaign.ProbeDenied, ControlAddressed: true,
		AuthedStage: campaign.ProbeStageResourceRead, AuthedStatus: campaign.ProbeAllowed, AuthedAddressed: true,
		VerifiedAt: "2026-07-12T00:00:00Z",
		Witness: campaign.Witness{
			SchemaVersion:                campaign.WitnessSchemaVersion,
			TopologyNormalizationVersion: campaign.WitnessTopologyNormalizationVersion,
			PublicationRevision:          1,
			PredictedEdgeKind:            campaign.PredictedEdgeKindCanReach,
			AgentID:                      agentID, AgentKind: "AgentInstance",
			CredentialID: credID, CredentialValueHash: "deadbeef",
			CredentialKind:     "Credential",
			CredentialMergeKey: campaign.CredentialMergeKeyValueHash,
			ServerID:           serverID, ServerKind: "MCPServer",
			ResourceID: resID, ResourceKind: "MCPResource", ResourceIdentityInput: uri,
			EvidenceNodeIDs:   []string{agentID, serverID, credID, resID},
			EvidenceNodeKinds: []string{"AgentInstance", "MCPServer", "Credential", "MCPResource"},
		},
	}
	scanID := "scan-camp-001"
	nodes, edges := ev.EvidenceGraph(scanID)
	scope := ingest.CanonicalCoverageKey("scan", "campaign", "cred-reach\x001\x00"+agentID+"\x00"+credID+"\x00"+serverID+"\x00"+resID)
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version: ingest.CurrentVersion, Type: ingest.IngestType,
			Origin:    testCollectionOrigin,
			Collector: "scan", CollectorVersion: "0.9.0-dev",
			Timestamp: "2026-07-12T00:00:00Z", ScanID: scanID,
			Collection: &ingest.CollectionReport{
				State: ingest.OutcomeComplete, CoverageKeys: []string{scope},
				Outcomes: []ingest.CollectionOutcome{{
					Collector: "scan", CoverageKey: scope, Target: serverID,
					Method: "campaign:cred-reach", State: ingest.OutcomeComplete, Items: len(edges),
				}},
			},
			Ruleset: ingest.EmptyRulesetManifest(), IdentitySchemes: ingest.CurrentIdentitySchemes(),
		},
		Graph: ingest.GraphData{Nodes: nodes, Edges: edges},
	}
	ingest.TagObservationDomain(&data.Graph, scope)
	return data
}

// TestValidatorAcceptsCampaignEvidence: the emitted CREDENTIAL_REACH_VERIFIED
// edge with reference_only endpoint nodes must pass ingest validation.
func TestValidatorAcceptsCampaignEvidence(t *testing.T) {
	data := campaignEvidenceIngest()
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("campaign evidence envelope rejected: %v", err)
	}
}

// TestValidatorRejectsCampaignMissingEndpoint: dropping a reference_only endpoint
// node must fail validation (the validator requires both edge endpoints present).
func TestValidatorRejectsCampaignMissingEndpoint(t *testing.T) {
	data := campaignEvidenceIngest()
	// Drop the source-agent endpoint node, keep the edge.
	var kept []ingest.Node
	for _, n := range data.Graph.Nodes {
		if !hasKind(n.Kinds, "AgentInstance") {
			kept = append(kept, n)
		}
	}
	data.Graph.Nodes = kept
	err := NewValidator().Validate(data)
	if err == nil {
		t.Fatal("edge with a missing endpoint node must be rejected")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	found := false
	for _, fe := range verr.Errors {
		if strings.Contains(fe.Message, "not present in graph.nodes") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a missing-endpoint field error, got: %+v", verr.Errors)
	}
}

func TestValidatorAcceptsCollectorProducedRootCoverage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AGENTHOUND_HOST_ID", testCollectionOrigin.HostID)
	t.Setenv("AGENTHOUND_NETWORK_REALM_ID", testCollectionOrigin.NetworkRealmID)
	configPath := filepath.Join(dir, "config.json")
	outputPath := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(
		configPath,
		[]byte(`{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}`),
		0o600,
	); err != nil {
		t.Fatalf("write config: %v", err)
	}

	originalArgs := os.Args
	os.Args = []string{
		"agenthound",
		"scan",
		"--config",
		"--path", configPath,
		"--scan-output", outputPath,
		"--quiet",
	}
	defer func() { os.Args = originalArgs }()

	if err := collectorcli.Execute(); err != nil {
		t.Fatalf("produce scan: %v", err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read scan: %v", err)
	}
	var data ingest.IngestData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	if err := NewValidator().Validate(&data); err != nil {
		t.Fatalf("collector-produced scan rejected: %v", err)
	}

	rootKey := ingest.CanonicalCoverageKey("config", "root", "collect")
	pathKey := ingest.CanonicalCoverageKey("config", "path", configPath)
	states := ingest.CoverageStates(data.Meta.Collection)
	if states[rootKey] != ingest.OutcomeComplete ||
		states[pathKey] != ingest.OutcomeComplete {
		t.Fatalf("collector coverage states = %v, want complete root and path", states)
	}
	if len(data.Meta.Collection.AuthoritativeRoots) != 0 {
		t.Fatalf(
			"targeted collector scan became authoritative: %+v",
			data.Meta.Collection.AuthoritativeRoots,
		)
	}
	for _, node := range data.Graph.Nodes {
		if len(node.ObservationDomains) != 1 || node.ObservationDomains[0] != pathKey {
			t.Fatalf("node %q ownership = %v, want path scope %q", node.ID, node.ObservationDomains, pathKey)
		}
	}
	for _, edge := range data.Graph.Edges {
		if len(edge.ObservationDomains) != 1 || edge.ObservationDomains[0] != pathKey {
			t.Fatalf(
				"edge %s-%s->%s ownership = %v, want path scope %q",
				edge.Source,
				edge.Kind,
				edge.Target,
				edge.ObservationDomains,
				pathKey,
			)
		}
	}
}

func TestValidatorAcceptsCanonicalLocalProcessAuthTuple(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties["auth_evidence"] = "local_process"
	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("canonical unknown/unknown/local_process tuple rejected: %v", err)
	}
}

func TestValidatorRejectsLocalProcessAnonymousTuple(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties["auth_method"] = "none"
	data.Graph.Nodes[0].Properties["auth_assurance"] = "unauthenticated"
	data.Graph.Nodes[0].Properties["auth_evidence"] = "local_process"
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].properties.auth_evidence",
	)
}

func TestValidatorAcceptsDeclaredObservationDomains(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	if err := v.Validate(data); err != nil {
		t.Fatalf("declared observation domain rejected: %v", err)
	}
}

func TestValidatorAcceptsPropertyNeutralNodeReference(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Properties = map[string]any{}
	data.Graph.Nodes[0].PropertySemantics = ingest.NodePropertySemanticsReferenceOnly

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("property-neutral node reference rejected: %v", err)
	}
}

func TestValidatorRejectsPropertiesOnNodeReference(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].PropertySemantics = ingest.NodePropertySemanticsReferenceOnly

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].properties",
	)
}

func TestValidatorRejectsUnknownNodePropertySemantics(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].PropertySemantics = "compatibility"

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].property_semantics",
	)
}

func TestValidatorAcceptsAuthoritativeRootActiveSet(t *testing.T) {
	data := validIngestData()
	child := data.Meta.Collection.CoverageKeys[0]
	root := ingest.CanonicalCoverageKey("mcp", "root", "collect")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.AuthoritativeRoots = []ingest.CoverageRoot{{
		CoverageKey:       root,
		ChildCoverageKeys: []string{child},
	}}
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		ingest.CollectionOutcome{
			Collector:   "mcp",
			CoverageKey: root,
			Target:      "mcp",
			Method:      "collect",
			State:       ingest.OutcomeComplete,
		},
	)

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("authoritative root active set rejected: %v", err)
	}
}

func TestValidatorRejectsAuthoritativeRootMissingDeclaredChild(t *testing.T) {
	data := validIngestData()
	root := ingest.CanonicalCoverageKey("mcp", "root", "collect")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, root)
	data.Meta.Collection.AuthoritativeRoots = []ingest.CoverageRoot{{
		CoverageKey: root,
	}}
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		ingest.CollectionOutcome{
			Collector:   "mcp",
			CoverageKey: root,
			Target:      "mcp",
			Method:      "collect",
			State:       ingest.OutcomeComplete,
		},
	)

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"meta.collection.authoritative_roots[0].child_coverage_keys",
	)
}

func TestValidatorAcceptsAllDependencyEdge(t *testing.T) {
	data := validIngestData()
	secondScope := ingest.CanonicalCoverageKey("mcp", "target", "https://second.example")
	data.Meta.Collection.CoverageKeys = append(data.Meta.Collection.CoverageKeys, secondScope)
	data.Meta.Collection.Outcomes = append(data.Meta.Collection.Outcomes, ingest.CollectionOutcome{
		Collector:   "mcp",
		CoverageKey: secondScope,
		Target:      "https://second.example",
		Method:      "enumerate",
		State:       ingest.OutcomeComplete,
	})
	data.Graph.Edges[0].ObservationDomains = append(
		data.Graph.Edges[0].ObservationDomains,
		secondScope,
	)
	data.Graph.Edges[0].ObservationSemantics = ingest.ObservationSemanticsAllDependencies

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("all-dependency edge rejected: %v", err)
	}
}

func TestValidatorRejectsAllDependenciesWithOneDomain(t *testing.T) {
	data := validIngestData()
	data.Graph.Edges[0].ObservationSemantics = ingest.ObservationSemanticsAllDependencies
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.edges[0].observation_semantics",
	)
}

func TestValidatorRejectsUndeclaredObservationDomain(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].ObservationDomains = []string{
		ingest.CanonicalCoverageKey("config", "path", "/tmp/config.json"),
	}

	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].observation_domains[0]")
}

func TestValidatorRejectsBadVersion(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Version = 99
	err := v.Validate(data)
	assertValidationError(t, err, "meta.version")
}

func TestValidatorRejectsV1(t *testing.T) {
	data := validIngestData()
	data.Meta.Version = 1
	assertValidationError(t, NewValidator().Validate(data), "meta.version")
}

func TestValidatorRequiresCompleteV2Metadata(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*ingest.IngestData)
		path string
	}{
		{"collection", func(data *ingest.IngestData) { data.Meta.Collection = nil }, "meta.collection"},
		{"ruleset", func(data *ingest.IngestData) { data.Meta.Ruleset = nil }, "meta.ruleset"},
		{"identity schemes", func(data *ingest.IngestData) { data.Meta.IdentitySchemes = nil }, "meta.identity_schemes"},
		{"fact ownership", func(data *ingest.IngestData) { data.Graph.Nodes[0].ObservationDomains = nil }, "graph.nodes[0].observation_domains"},
		{"edge source kind", func(data *ingest.IngestData) { data.Graph.Edges[0].SourceKind = "" }, "graph.edges[0].source_kind"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			test.edit(data)
			assertValidationError(t, NewValidator().Validate(data), test.path)
		})
	}
}

func TestValidatorRejectsLegacyPropertyAliases(t *testing.T) {
	for alias := range forbiddenPropertyAliases {
		t.Run(alias, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Nodes[1].Properties[alias] = true
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[1].properties."+alias,
			)
		})
	}
}

func TestValidatorRejectsRemovedGraphCompatibilityProperties(t *testing.T) {
	for _, property := range removedGraphProperties {
		t.Run(property, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Nodes[0].Properties[property] = true
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.nodes[0].properties."+property,
			)
		})
	}
}

func TestValidatorRequiresOrderedStdioIdentity(t *testing.T) {
	t.Run("metadata", func(t *testing.T) {
		data := validIngestData()
		data.Meta.IdentitySchemes[0].Scheme = "mcp_stdio_v1_sorted"
		data.Meta.IdentitySchemes[0].Version = 1
		assertValidationError(
			t,
			NewValidator().Validate(data),
			"meta.identity_schemes[0]",
		)
	})
	t.Run("node", func(t *testing.T) {
		data := validIngestData()
		data.Graph.Nodes[0].Properties["transport"] = "stdio"
		data.Graph.Nodes[0].Properties["id_scheme"] = "unordered"
		assertValidationError(
			t,
			NewValidator().Validate(data),
			"graph.nodes[0].properties.id_scheme",
		)
	})
}

func TestValidatorRequiresCurrentStdioParentAndChildIDs(t *testing.T) {
	currentData := func() *ingest.IngestData {
		data := validIngestData()
		parentID := ingest.ComputeMCPServerID(
			"stdio",
			"npx",
			"-y",
			"@modelcontextprotocol/server-postgres",
		)
		childID := ingest.ComputeNodeID("MCPTool", parentID, "tool")
		data.Graph.Nodes[0].ID = parentID
		data.Graph.Nodes[0].Properties["transport"] = "stdio"
		data.Graph.Nodes[0].Properties["command"] = "npx"
		data.Graph.Nodes[0].Properties["args"] = []string{
			"-y",
			"@modelcontextprotocol/server-postgres",
		}
		data.Graph.Nodes[0].Properties["id_scheme"] = ingest.MCPStdioIdentitySchemeV2
		data.Graph.Nodes[1].ID = childID
		data.Graph.Edges[0].Source = parentID
		data.Graph.Edges[0].Target = childID
		return data
	}

	if err := NewValidator().Validate(currentData()); err != nil {
		t.Fatalf("current stdio identities rejected: %v", err)
	}
	t.Run("parent", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[0].ID = "sha256:former-parent"
		data.Graph.Edges[0].Source = data.Graph.Nodes[0].ID
		assertValidationError(t, NewValidator().Validate(data), "graph.nodes[0].id")
	})
	t.Run("child", func(t *testing.T) {
		data := currentData()
		data.Graph.Nodes[1].ID = "sha256:former-child"
		data.Graph.Edges[0].Target = data.Graph.Nodes[1].ID
		assertValidationError(t, NewValidator().Validate(data), "graph.edges[0].target")
	})
}

func TestValidatorRejectsBadType(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Type = "wrong"
	err := v.Validate(data)
	assertValidationError(t, err, "meta.type")
}

func TestValidatorRejectsBadCollector(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.Collector = "unknown"
	err := v.Validate(data)
	assertValidationError(t, err, "meta.collector")
}

func TestValidatorRejectsEmptyScanID(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Meta.ScanID = ""
	err := v.Validate(data)
	assertValidationError(t, err, "meta.scan_id")
}

func TestValidatorRejectsEmptyNodeID(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].ID = ""
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].id")
}

func TestValidatorRejectsEmptyNodeKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = nil
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].kinds")
}

func TestValidatorRejectsInvalidNodeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = []string{"FakeNode"}
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[0].kinds[0]")
}

func TestValidatorRejectsConflictingConcreteKindsInOneNode(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{{
		ID:    "shared-role",
		Kinds: []string{"MCPServer", "MCPTool"},
		Properties: map[string]any{
			"auth_method":    "unknown",
			"auth_assurance": "unknown",
			"auth_evidence":  "unknown",
		},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}
	data.Graph.Edges = []ingest.Edge{{
		Source:             "shared-role",
		Target:             "shared-role",
		Kind:               "PROVIDES_TOOL",
		SourceKind:         "MCPServer",
		TargetKind:         "MCPTool",
		Properties:         map[string]any{"risk_weight": 0.1},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].kinds",
	)
}

func TestValidatorRejectsConflictingConcreteKindsAcrossDuplicateRows(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[1].ID = data.Graph.Nodes[0].ID
	data.Graph.Edges[0].Target = data.Graph.Nodes[0].ID

	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[1].kinds",
	)
}

func TestValidatorAcceptsDocumentedUmbrellaAndRepeatedConcreteRows(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes,
		ingest.Node{
			ID:                 "sha256:gateway",
			Kinds:              []string{"LiteLLMGateway", "AIService"},
			Properties:         map[string]any{"name": "gateway"},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
		ingest.Node{
			ID:    data.Graph.Nodes[0].ID,
			Kinds: []string{"MCPServer"},
			Properties: map[string]any{
				"name": "same server", "auth_method": "unknown",
				"auth_assurance": "unknown", "auth_evidence": "unknown",
			},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
	)

	if err := NewValidator().Validate(data); err != nil {
		t.Fatalf("valid umbrella/repeated concrete rows rejected: %v", err)
	}
}

func TestValidatorRejectsUndocumentedUmbrellaCompanion(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes[0].Kinds = []string{"MCPServer", "AIService"}
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[0].kinds",
	)
}

func TestValidatorRejectsCredentialWithoutValueHash(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:                 "sha256:cred",
		Kinds:              []string{"Credential"},
		Properties:         map[string]any{"name": "API_KEY"},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	err := v.Validate(data)
	assertValidationError(t, err, "graph.nodes[2].properties.value_hash")
}

func TestValidatorAcceptsCredentialWithValueHash(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:    "sha256:cred",
		Kinds: []string{"Credential"},
		Properties: map[string]any{
			"name": "API_KEY", "value_hash": "sha256:abc",
			"merge_key": "value_hash", "identity_basis": "value_hash",
			"material_status": "observed", "exposure_status": "exposed",
		},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected credential with value_hash to validate, got: %v", err)
	}
}

func TestValidatorRejectsCredentialWithoutCanonicalMergeKey(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes, ingest.Node{
		ID:    "sha256:cred",
		Kinds: []string{"Credential"},
		Properties: map[string]any{
			"name": "API_KEY", "value_hash": "sha256:abc",
			"identity_basis": "value_hash", "material_status": "observed",
			"exposure_status": "exposed",
		},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.nodes[2].properties.merge_key",
	)
}

func TestValidatorRejectsEmptyEdgeSource(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Source = ""
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source")
}

func TestValidatorRejectsInvalidEdgeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Kind = "FAKE_EDGE"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].kind")
}

func TestValidatorRejectsCompositeEdgeKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Kind = "CAN_REACH"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].kind")
}

func TestValidatorRejectsInvalidEdgeSourceKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer) WITH edge MATCH (z) DETACH DELETE z //"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsInvalidEdgeTargetKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].TargetKind = "MCPTool {x:1}) DETACH DELETE n //"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target_kind")
}

func TestValidatorAcceptsValidExplicitEdgeKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer"
	data.Graph.Edges[0].TargetKind = "MCPTool"
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected explicit valid edge kinds to validate, got: %v", err)
	}
}

func TestValidatorRejectsIncompatibleSourceKind(t *testing.T) {
	// MCPTool is a valid node label but not a valid *source* for PROVIDES_TOOL
	// (which must be MCPServer -> MCPTool). AH-UI-30: reject the inverted role.
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPTool"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsIncompatibleTargetKind(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].TargetKind = "MCPServer"
	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target_kind")
}

func TestValidatorAcceptsCompatibleEndpointKinds(t *testing.T) {
	// PROVIDES_RESOURCE permits multiple valid sources; JupyterServer is one.
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = append(data.Graph.Nodes,
		ingest.Node{ID: "sha256:jup", Kinds: []string{"JupyterServer"}, Properties: map[string]any{"name": "j"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
		ingest.Node{ID: "sha256:res", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "r"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
	)
	data.Graph.Edges = append(data.Graph.Edges, ingest.Edge{
		Source: "sha256:jup", Target: "sha256:res", Kind: "PROVIDES_RESOURCE",
		SourceKind: "JupyterServer", TargetKind: "MCPResource",
		Properties:         map[string]any{"risk_weight": 0.2},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	})
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected compatible endpoint kinds to validate, got: %v", err)
	}
}

func TestValidatorAcceptsExplicitAlternateEndpointKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{ID: "sha256:jup", Kinds: []string{"JupyterServer", "AIService"}, Properties: map[string]any{"name": "j"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
		{ID: "sha256:res", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "r"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source: "sha256:jup", Target: "sha256:res", Kind: "PROVIDES_RESOURCE",
		SourceKind: "JupyterServer", TargetKind: "MCPResource",
		Properties:         map[string]any{"risk_weight": 0.2},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected omitted kinds to resolve from actual nodes, got: %v", err)
	}
}

func TestValidatorAcceptsConcreteExposesEndpointKinds(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{ID: "sha256:webui", Kinds: []string{"OpenWebUIInstance", "AIService"}, Properties: map[string]any{"name": "webui"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
		{ID: "sha256:ollama", Kinds: []string{"OllamaInstance", "AIService"}, Properties: map[string]any{"name": "ollama"}, ObservationDomains: data.Graph.Nodes[0].ObservationDomains},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source:             "sha256:webui",
		Target:             "sha256:ollama",
		Kind:               "EXPOSES",
		SourceKind:         "OpenWebUIInstance",
		TargetKind:         "OllamaInstance",
		Properties:         map[string]any{"risk_weight": 0.3},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected producer's concrete EXPOSES labels to validate, got: %v", err)
	}
}

func TestValidatorRejectsDeclaredKindThatDoesNotMatchReferencedNode(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].SourceKind = "MCPServer"
	data.Graph.Edges[0].TargetKind = "MCPTool"
	// Both declared kinds are valid for PROVIDES_TOOL, but the referenced
	// source node does not actually carry the declared MCPServer label.
	data.Graph.Nodes[0].Kinds = []string{"MCPTool"}

	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].source_kind")
}

func TestValidatorRejectsMissingReferencedNode(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Edges[0].Target = "sha256:not-in-artifact"

	err := v.Validate(data)
	assertValidationError(t, err, "graph.edges[0].target")
}

func TestValidatorAcceptsReferencedUmbrellaLabel(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{
		{
			ID:                 "sha256:gateway",
			Kinds:              []string{"LiteLLMGateway", "AIService"},
			Properties:         map[string]any{"name": "gateway"},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
		{
			ID:    "sha256:credential",
			Kinds: []string{"Credential"},
			Properties: map[string]any{
				"name": "key", "value_hash": "abc",
				"merge_key": "value_hash", "identity_basis": "value_hash",
				"material_status": "observed", "exposure_status": "exposed",
			},
			ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
		},
	}
	data.Graph.Edges = []ingest.Edge{{
		Source: "sha256:gateway", Target: "sha256:credential",
		Kind: "EXPOSES_CREDENTIAL", SourceKind: "AIService", TargetKind: "Credential",
		Properties:         map[string]any{"risk_weight": 0.1},
		ObservationDomains: data.Graph.Nodes[0].ObservationDomains,
	}}

	if err := v.Validate(data); err != nil {
		t.Fatalf("expected actual AIService umbrella label to validate, got: %v", err)
	}
}

func TestValidatorRejectsRawEdgeMissingRiskWeight(t *testing.T) {
	data := validIngestData()
	delete(data.Graph.Edges[0].Properties, "risk_weight")
	assertValidationError(
		t,
		NewValidator().Validate(data),
		"graph.edges[0].properties.risk_weight",
	)
}

func TestValidatorRejectsRawEdgeInvalidRiskWeight(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"string", "0.1"},
		{"bool", true},
		{"nan", math.NaN()},
		{"positive infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},
		{"negative", -0.1},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Edges[0].Properties["risk_weight"] = test.value
			assertValidationError(
				t,
				NewValidator().Validate(data),
				"graph.edges[0].properties.risk_weight",
			)
		})
	}
}

func TestValidatorAcceptsRawEdgeRiskWeight(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"zero float", 0.0},
		{"positive float", 0.75},
		{"json number", json.Number("0.4")},
		{"native int", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := validIngestData()
			data.Graph.Edges[0].Properties["risk_weight"] = test.value
			if err := NewValidator().Validate(data); err != nil {
				t.Fatalf("expected valid risk_weight %v to pass, got: %v", test.value, err)
			}
		})
	}
}

func TestValidatorCollectsAllErrors(t *testing.T) {
	v := NewValidator()
	data := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:   99,
			Type:      "wrong",
			Collector: "bad",
			ScanID:    "",
		},
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{{ID: "", Kinds: nil}},
			Edges: []ingest.Edge{{Source: "", Target: "", Kind: "FAKE"}},
		},
	}
	err := v.Validate(data)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	if len(ve.Errors) < 7 {
		t.Errorf("expected at least 7 errors, got %d: %+v", len(ve.Errors), ve.Errors)
	}
}

func TestValidatorAcceptsEmptyGraph(t *testing.T) {
	v := NewValidator()
	data := validIngestData()
	data.Graph.Nodes = []ingest.Node{}
	data.Graph.Edges = []ingest.Edge{}
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected no error for empty graph, got: %v", err)
	}
}

func TestValidatorRejectsNullGraphCollections(t *testing.T) {
	data := validIngestData()
	data.Graph.Nodes = nil
	data.Graph.Edges = nil
	err := NewValidator().Validate(data)
	assertValidationError(t, err, "graph.nodes")
	assertValidationError(t, err, "graph.edges")
}

func TestValidationError_Error(t *testing.T) {
	ve := &ValidationError{
		Errors: []FieldError{
			{Path: "meta.version", Message: "must be 2"},
			{Path: "meta.type", Message: "must be 'agenthound-ingest'"},
			{Path: "meta.scan_id", Message: "must not be empty"},
		},
	}
	got := ve.Error()
	if got != "validation failed: 3 errors" {
		t.Errorf("Error() = %q, want %q", got, "validation failed: 3 errors")
	}
}

func assertValidationError(t *testing.T, err error, expectedPath string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	for _, fe := range ve.Errors {
		if fe.Path == expectedPath {
			return
		}
	}
	t.Errorf("expected error at path %q, got errors: %+v", expectedPath, ve.Errors)
}

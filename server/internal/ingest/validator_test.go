package ingest

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func validIngestData() *ingest.IngestData {
	scope := ingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	return &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          ingest.CurrentVersion,
			Type:             ingest.IngestType,
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

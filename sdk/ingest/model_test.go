package ingest

import (
	"encoding/json"
	"testing"
)

func TestNodeJSONRoundTrip(t *testing.T) {
	n := Node{
		ID:    "sha256:abc123",
		Kinds: []string{"MCPServer"},
		Properties: map[string]any{
			"name":      "test-server",
			"transport": "stdio",
		},
	}

	data, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Node
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != n.ID {
		t.Errorf("ID: got %q, want %q", got.ID, n.ID)
	}
	if len(got.Kinds) != 1 || got.Kinds[0] != "MCPServer" {
		t.Errorf("Kinds: got %v, want [MCPServer]", got.Kinds)
	}
	if got.Properties["name"] != "test-server" {
		t.Errorf("Properties[name]: got %v, want test-server", got.Properties["name"])
	}
}

func TestReferenceOnlyNodeJSONRoundTrip(t *testing.T) {
	node := Node{
		ID:                "sha256:reference",
		Kinds:             []string{"LiteLLMGateway", "AIService"},
		Properties:        map[string]any{},
		PropertySemantics: NodePropertySemanticsReferenceOnly,
	}

	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Node
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PropertySemantics != NodePropertySemanticsReferenceOnly {
		t.Errorf("PropertySemantics: got %q, want reference_only", got.PropertySemantics)
	}
	if got.Properties == nil || len(got.Properties) != 0 {
		t.Errorf("Properties: got %+v, want empty object", got.Properties)
	}
}

func TestEdgeJSONRoundTrip(t *testing.T) {
	e := Edge{
		Source: "sha256:aaa",
		Target: "sha256:bbb",
		Kind:   "PROVIDES_TOOL",
		Properties: map[string]any{
			"confidence": 1.0,
		},
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Edge
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Source != e.Source || got.Target != e.Target || got.Kind != e.Kind {
		t.Errorf("edge mismatch: got %+v, want %+v", got, e)
	}
}

func TestIngestDataJSONRoundTrip(t *testing.T) {
	input := `{
		"meta": {
			"version": 4,
			"type": "agenthound-ingest",
			"collector": "mcp",
			"collector_version": "0.1.0",
			"timestamp": "2026-04-06T10:30:00Z",
			"scan_id": "scan-001",
			"identity": {"scheme":"agenthound_collection_v1","version":1,"collection_point_id":"sha256:point","network_context_id":"sha256:network","quality":"strong","network_quality":"strong","network_class":"private","evidence":[],"network_evidence":[]},
			"collection": {
				"state": "complete",
				"coverage_keys": ["mcp:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
				"outcomes": [{
					"collector": "mcp",
					"coverage_key": "mcp:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"target": "https://mcp.example",
					"method": "enumerate",
					"state": "complete"
				}]
			},
			"ruleset": {
				"digest": "sha256:rules",
				"load_state": "complete",
				"authenticity": "unverified"
			},
			"identity_schemes": [{
				"entity_kind": "MCPServer",
				"transport": "stdio",
				"scheme": "mcp_stdio_v3_hashed_argv",
				"version": 3
			}]
		},
		"graph": {
			"nodes": [
				{"id": "sha256:aaa", "kinds": ["MCPServer"], "properties": {"name": "srv"}, "observation_domains": ["mcp:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},
				{"id": "sha256:bbb", "kinds": ["MCPTool"], "properties": {"name": "tool"}, "observation_domains": ["mcp:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}
			],
			"edges": [{"source": "sha256:aaa", "target": "sha256:bbb", "kind": "PROVIDES_TOOL", "source_kind": "MCPServer", "target_kind": "MCPTool", "properties": {}, "observation_domains": ["mcp:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}]
		}
	}`

	var d IngestData
	if err := json.Unmarshal([]byte(input), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if d.Meta.Version != CurrentVersion {
		t.Errorf("meta.version: got %d, want %d", d.Meta.Version, CurrentVersion)
	}
	if d.Meta.Collector != "mcp" {
		t.Errorf("meta.collector: got %q, want mcp", d.Meta.Collector)
	}
	if len(d.Graph.Nodes) != 2 {
		t.Errorf("nodes count: got %d, want 2", len(d.Graph.Nodes))
	}
	if len(d.Graph.Edges) != 1 {
		t.Errorf("edges count: got %d, want 1", len(d.Graph.Edges))
	}
	if d.Meta.Collection == nil || d.Meta.Ruleset == nil || len(d.Meta.IdentitySchemes) == 0 {
		t.Fatal("strict v4 metadata was not preserved")
	}
	if d.Meta.Identity.Scheme != CollectionIdentityScheme {
		t.Fatalf("identity = %+v", d.Meta.Identity)
	}
}

func TestCurrentIdentitySchemesUsesHashedArgvV3(t *testing.T) {
	schemes := CurrentIdentitySchemes()
	if len(schemes) != 1 || schemes[0].EntityKind != "MCPServer" ||
		schemes[0].Transport != "stdio" ||
		schemes[0].Scheme != MCPStdioIdentitySchemeV3 || schemes[0].Version != 3 {
		t.Fatalf("current identity schemes = %+v, want stdio MCPServer hashed-argv v3", schemes)
	}
}

func TestIngestEvidenceMetadataJSONRoundTrip(t *testing.T) {
	input := IngestData{
		Meta: IngestMeta{
			Version:   CurrentVersion,
			Type:      "agenthound-ingest",
			Collector: "scan",
			ScanID:    "scan-001",
			Collection: &CollectionReport{
				State:        OutcomePartial,
				CoverageKeys: []string{"a2a:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				Outcomes: []CollectionOutcome{{
					Collector:   "a2a",
					CoverageKey: "a2a:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Target:      "https://agent.example",
					Method:      "agent_card",
					State:       OutcomeFailed,
					Error:       "connection refused",
				}},
			},
			Ruleset: &RulesetManifest{
				Digest:       "sha256:rules",
				LoadState:    OutcomeComplete,
				Authenticity: "unverified",
				Entries: []RuleManifestEntry{{
					Type:             "text",
					ID:               "rule",
					Version:          1,
					SemanticSHA256:   "sha256:entry",
					Source:           "custom",
					EffectiveMatcher: json.RawMessage(`{"type":"keyword","keywords":["test"]}`),
				}},
			},
			IdentitySchemes: []IdentityScheme{{
				EntityKind: "MCPServer",
				Transport:  "stdio",
				Scheme:     MCPStdioIdentitySchemeV3,
				Version:    3,
			}},
		},
		Graph: GraphData{Nodes: []Node{}, Edges: []Edge{}},
	}

	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got IngestData
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Meta.Collection == nil || got.Meta.Collection.State != OutcomePartial {
		t.Fatalf("collection metadata lost: %+v", got.Meta.Collection)
	}
	if got.Meta.Ruleset == nil || got.Meta.Ruleset.Authenticity != "unverified" {
		t.Fatalf("ruleset metadata lost: %+v", got.Meta.Ruleset)
	}
	if len(got.Meta.Ruleset.Entries) != 1 ||
		string(got.Meta.Ruleset.Entries[0].EffectiveMatcher) !=
			`{"type":"keyword","keywords":["test"]}` {
		t.Fatalf("effective matcher metadata lost: %+v", got.Meta.Ruleset)
	}
	if len(got.Meta.IdentitySchemes) != 1 ||
		got.Meta.IdentitySchemes[0].Scheme != MCPStdioIdentitySchemeV3 {
		t.Fatalf("identity metadata lost: %+v", got.Meta.IdentitySchemes)
	}
}

func TestAllowedNodeKindsComplete(t *testing.T) {
	if len(AllowedNodeKinds) != 23 {
		t.Errorf("AllowedNodeKinds: got %d entries, want 23", len(AllowedNodeKinds))
	}
}

func TestAllNodeLabelsComplete(t *testing.T) {
	if len(AllNodeLabels) != 23 {
		t.Errorf("AllNodeLabels: got %d entries, want 23", len(AllNodeLabels))
	}
}

func TestAllowedEdgeKindsComplete(t *testing.T) {
	if len(AllowedEdgeKinds) != 32 {
		t.Errorf("AllowedEdgeKinds: got %d entries, want 32", len(AllowedEdgeKinds))
	}
}

func TestRawEdgeKindsComplete(t *testing.T) {
	if len(RawEdgeKinds) != 20 {
		t.Errorf("RawEdgeKinds: got %d entries, want 20", len(RawEdgeKinds))
	}
}

// TestCampaignEdgeKindsRegistered guards the campaign-runner additions.
// The differential credential-reach scenario emits CREDENTIAL_REACH_VERIFIED
// (AgentInstance→MCPResource) as per-agent supporting evidence that upgrades the existing
// CAN_REACH finding, and PUBLIC_ACCESS_OBSERVED (MCPServer→MCPResource) as an
// anonymous-access fact. Both must be raw so the ingest validator accepts them
// and so PUBLIC_ACCESS_OBSERVED never auto-creates a finding (findings derive
// only from composite edges).
func TestCampaignEdgeKindsRegistered(t *testing.T) {
	for _, kind := range []string{"CREDENTIAL_REACH_VERIFIED", "PUBLIC_ACCESS_OBSERVED"} {
		if !RawEdgeKinds[kind] {
			t.Errorf("RawEdgeKinds missing campaign edge %q (validator gate rejects ingest)", kind)
		}
		if !AllowedEdgeKinds[kind] {
			t.Errorf("AllowedEdgeKinds missing campaign edge %q", kind)
		}
		if _, ok := EdgeKindEndpoints[kind]; !ok {
			t.Errorf("EdgeKindEndpoints missing campaign edge %q", kind)
		}
	}
	if ep := EdgeKindEndpoints["CREDENTIAL_REACH_VERIFIED"]; len(ep.SourceKinds) == 0 ||
		ep.SourceKinds[0] != "AgentInstance" || len(ep.TargetKinds) == 0 || ep.TargetKinds[0] != "MCPResource" {
		t.Errorf("CREDENTIAL_REACH_VERIFIED endpoints: got %+v, want AgentInstance->MCPResource", ep)
	}
	if ep := EdgeKindEndpoints["PUBLIC_ACCESS_OBSERVED"]; len(ep.SourceKinds) == 0 ||
		ep.SourceKinds[0] != "MCPServer" || len(ep.TargetKinds) == 0 || ep.TargetKinds[0] != "MCPResource" {
		t.Errorf("PUBLIC_ACCESS_OBSERVED endpoints: got %+v, want MCPServer->MCPResource", ep)
	}
}

func TestRawEdgeKindsSubsetOfAllowed(t *testing.T) {
	for kind := range RawEdgeKinds {
		if !AllowedEdgeKinds[kind] {
			t.Errorf("RawEdgeKind %q not in AllowedEdgeKinds", kind)
		}
	}
}

// TestAIServiceKindsRegistered guards against accidental removal of the
// AI-service node kinds + edge kinds. The credential-chain analysis and every
// downstream consumer (writer, schema, post-processors, UI) depends on these
// being present in their respective maps.
func TestAIServiceKindsRegistered(t *testing.T) {
	wantNodeKinds := []string{
		"OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
		"LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance",
		"AIService",
	}
	for _, k := range wantNodeKinds {
		if !AllowedNodeKinds[k] {
			t.Errorf("AllowedNodeKinds missing AI-service kind %q", k)
		}
	}

	// AllNodeLabels is a slice; convert to a set for membership tests.
	labelSet := make(map[string]bool, len(AllNodeLabels))
	for _, l := range AllNodeLabels {
		labelSet[l] = true
	}
	for _, k := range wantNodeKinds {
		if !labelSet[k] {
			t.Errorf("AllNodeLabels missing AI-service label %q", k)
		}
	}

	wantEdgeKinds := []string{"EXPOSES", "EXPOSES_CREDENTIAL"}
	for _, k := range wantEdgeKinds {
		if !RawEdgeKinds[k] {
			t.Errorf("RawEdgeKinds missing AI-service edge %q (the ingest validator will reject it)", k)
		}
		if !AllowedEdgeKinds[k] {
			t.Errorf("AllowedEdgeKinds missing AI-service edge %q", k)
		}
	}

	// AIService must be in UmbrellaLabels — the schema-init loop relies on
	// this to skip the umbrella when creating uniqueness constraints.
	if !UmbrellaLabels["AIService"] {
		t.Error("UmbrellaLabels missing AIService — schema-init will create a duplicate constraint that breaks multi-label MERGE")
	}
}

// TestAIModelKindRegistered guards the AIModel + PROVIDES_MODEL contract.
// The Ollama Looter (modules/ollamaloot) emits one :AIModel per model surfaced
// via /api/tags + /api/show, joined by an OllamaInstance -[PROVIDES_MODEL]->
// AIModel edge. AIModel is NOT an umbrella — it's a per-kind label that gets
// its own uniqueness constraint via the AllNodeLabels loop.
func TestAIModelKindRegistered(t *testing.T) {
	if !AllowedNodeKinds["AIModel"] {
		t.Error("AllowedNodeKinds missing kind \"AIModel\"")
	}
	labelSet := make(map[string]bool, len(AllNodeLabels))
	for _, l := range AllNodeLabels {
		labelSet[l] = true
	}
	if !labelSet["AIModel"] {
		t.Error("AllNodeLabels missing label \"AIModel\"")
	}
	if UmbrellaLabels["AIModel"] {
		t.Error("AIModel must NOT be in UmbrellaLabels — it gets its own uniqueness constraint")
	}
	if !RawEdgeKinds["PROVIDES_MODEL"] {
		t.Error("RawEdgeKinds missing edge \"PROVIDES_MODEL\"")
	}
	if !AllowedEdgeKinds["PROVIDES_MODEL"] {
		t.Error("AllowedEdgeKinds missing edge \"PROVIDES_MODEL\"")
	}
	ep, ok := EdgeKindEndpoints["PROVIDES_MODEL"]
	if !ok {
		t.Fatal("EdgeKindEndpoints missing PROVIDES_MODEL")
	}
	if len(ep.SourceKinds) == 0 || ep.SourceKinds[0] != "OllamaInstance" {
		t.Errorf("PROVIDES_MODEL source kinds: got %v, want [OllamaInstance]", ep.SourceKinds)
	}
	if len(ep.TargetKinds) == 0 || ep.TargetKinds[0] != "AIModel" {
		t.Errorf("PROVIDES_MODEL target kinds: got %v, want [AIModel]", ep.TargetKinds)
	}
}

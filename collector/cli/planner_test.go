package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	a2acollector "github.com/adithyan-ak/agenthound/modules/a2a"
	_ "github.com/adithyan-ak/agenthound/modules/litellmcollect"
	_ "github.com/adithyan-ak/agenthound/modules/ollamacollect"
	_ "github.com/adithyan-ak/agenthound/modules/qdrantcollect"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/checkpoint"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

type plannerTestAction struct {
	id         string
	candidates []Candidate
}

func (a plannerTestAction) ID() string { return a.id }
func (a plannerTestAction) Candidates(View) []Candidate {
	return append([]Candidate(nil), a.candidates...)
}
func (a plannerTestAction) Execute(context.Context, Candidate, Journal) (Result, error) {
	return Result{}, nil
}

func TestNextPlannerCandidateIsDeterministic(t *testing.T) {
	actions := []PlannerAction{
		plannerTestAction{id: "z", candidates: []Candidate{{Key: "b", Priority: 2}}},
		plannerTestAction{id: "a", candidates: []Candidate{{Key: "z", Priority: 1}, {Key: "a", Priority: 1}}},
	}
	_, got, ok := nextPlannerCandidate(actions, buildPlannerView(ingest.GraphData{}, nil, map[string]bool{}, false, false))
	if !ok || got.Key != "a" {
		t.Fatalf("next = (%q, %t), want a", got.Key, ok)
	}
}

func TestNextPlannerCandidateSkipsCompletedKeys(t *testing.T) {
	action := plannerTestAction{id: "a", candidates: []Candidate{{Key: "a", Priority: 1}, {Key: "b", Priority: 2}}}
	_, got, ok := nextPlannerCandidate([]PlannerAction{action}, buildPlannerView(ingest.GraphData{}, nil, map[string]bool{"a": true}, false, false))
	if !ok || got.Key != "b" {
		t.Fatalf("next = (%q, %t), want b", got.Key, ok)
	}
}

func TestPlannerIndexesOnlyObservedCredentialMaterial(t *testing.T) {
	graph := ingest.GraphData{Nodes: []ingest.Node{
		{ID: "raw", Kinds: []string{"Credential"}, Properties: map[string]any{
			"value": "sk-observed", "material_status": string(common.CredentialMaterialObserved),
		}},
		{ID: "env", Kinds: []string{"Credential"}, Properties: map[string]any{
			"value": "$UNRESOLVED", "material_status": string(common.CredentialMaterialUnobserved),
		}},
		{ID: "masked", Kinds: []string{"Credential"}, Properties: map[string]any{
			"value": "sk-...", "material_status": string(common.CredentialMaterialMasked),
		}},
	}}

	view := buildPlannerView(graph, nil, map[string]bool{}, false, false)
	if got := view.Credentials["raw"]; got != "sk-observed" {
		t.Fatalf("observed credential = %q, want raw value", got)
	}
	for _, id := range []string{"env", "masked"} {
		if _, executable := view.Credentials[id]; executable {
			t.Fatalf("credential %q with non-observed material became executable", id)
		}
	}
}

func TestBearerCandidatesRequireDeclaredBearerMethod(t *testing.T) {
	for _, test := range []struct {
		name       string
		properties map[string]any
		want       bool
	}{
		{name: "singular bearer", properties: map[string]any{"auth_method": string(common.AuthBearer)}, want: true},
		{name: "aggregated bearer", properties: map[string]any{"auth_methods": []string{string(common.AuthAPIKey), string(common.AuthBearer)}}, want: true},
		{name: "decoded aggregate", properties: map[string]any{"auth_methods": []any{string(common.AuthBearer)}}, want: true},
		{name: "basic", properties: map[string]any{"auth_method": string(common.AuthBasic)}},
		{name: "custom", properties: map[string]any{"auth_method": string(common.AuthCustom)}},
		{name: "unknown", properties: map[string]any{"auth_method": string(common.AuthUnknown)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			node := ingest.Node{Properties: test.properties}
			if got := bearerCredential(node); got != test.want {
				t.Fatalf("bearerCredential() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAggregatedCredentialHintsPreserveServiceCompatibility(t *testing.T) {
	credential := ingest.Node{Properties: map[string]any{
		"auth_methods": []string{string(common.AuthAPIKey), string(common.AuthBearer)},
		"names":        []string{"Authorization", "JUPYTER_TOKEN"},
		"types":        []string{"hardcoded"},
		"formats":      []string{"generic"},
	}}
	for _, service := range []string{"litellm", "openwebui", "jupyter"} {
		if !credentialCompatibleWithService(credential, service) {
			t.Fatalf("aggregated credential was not compatible with %s", service)
		}
	}
}

func TestServiceCollectCandidatesDeduplicateCredentialValuesPerEndpoint(t *testing.T) {
	const endpoint = "https://litellm.example"
	credential := func(id, value string) ingest.Node {
		return ingest.Node{ID: id, Kinds: []string{"Credential"}, Properties: map[string]any{
			"value": value, "value_hash": common.HashCredentialValue(value),
			"material_status": string(common.CredentialMaterialObserved),
			"auth_method":     string(common.AuthAPIKey),
			"type":            "master_key",
		}}
	}
	graph := ingest.GraphData{Nodes: []ingest.Node{
		{ID: "gateway", Kinds: []string{"LiteLLMGateway", "AIService"}, Properties: map[string]any{
			"endpoint": endpoint,
		}},
		credential("shared-a", "sk-shared-master-key"),
		credential("shared-b", "sk-shared-master-key"),
		credential("distinct", "sk-distinct-master-key"),
	}}

	candidates := (serviceCollectAction{}).Candidates(
		buildPlannerView(graph, nil, map[string]bool{}, false, false),
	)
	if len(candidates) != 2 {
		t.Fatalf("candidates = %+v, want two distinct credential values", candidates)
	}
	values := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		if candidate.ModuleID != "litellm.collect" || candidate.Target.Address != endpoint {
			t.Fatalf("candidate = %+v, want LiteLLM endpoint", candidate)
		}
		values[candidate.Inputs["credential"]] = true
	}
	for _, want := range []string{"sk-shared-master-key", "sk-distinct-master-key"} {
		if !values[want] {
			t.Errorf("candidate for %q missing: %+v", want, candidates)
		}
	}
}

func TestCredentialReachDeduplicatesByValueHashAndPrefersDirectAttribution(t *testing.T) {
	const (
		serverID   = "server"
		resourceID = "resource"
		identityID = "identity"
		directID   = "z-direct"
		otherID    = "a-unrelated"
		value      = "shared-bearer-value"
	)
	credential := func(id string) ingest.Node {
		return ingest.Node{ID: id, Kinds: []string{"Credential"}, Properties: map[string]any{
			"value": value, "value_hash": common.HashCredentialValue(value),
			"material_status": string(common.CredentialMaterialObserved),
			"auth_method":     string(common.AuthBearer),
		}}
	}
	graph := ingest.GraphData{
		Nodes: []ingest.Node{
			{ID: serverID, Kinds: []string{"MCPServer"}, Properties: map[string]any{
				"endpoint": "https://mcp.example/mcp", "transport": "http",
			}},
			{ID: resourceID, Kinds: []string{"MCPResource"}, Properties: map[string]any{"uri": "secret://one"}},
			{ID: identityID, Kinds: []string{"Identity"}, Properties: map[string]any{}},
			credential(otherID), credential(directID),
		},
		Edges: []ingest.Edge{
			{Source: serverID, Target: resourceID, Kind: "PROVIDES_RESOURCE"},
			{Source: serverID, Target: identityID, Kind: "AUTHENTICATES_WITH"},
			{Source: identityID, Target: directID, Kind: "USES_CREDENTIAL"},
		},
	}
	view := buildPlannerView(graph, nil, map[string]bool{}, false, false)
	candidates := (credentialReachAction{}).Candidates(view)
	if len(candidates) != 1 {
		t.Fatalf("candidates = %+v, want one value-hash-deduplicated candidate", candidates)
	}
	if candidates[0].CredentialID != directID {
		t.Fatalf("credential attribution = %q, want direct %q", candidates[0].CredentialID, directID)
	}
}

func TestCredentialReachSkipsResourceAlreadyProvenPublic(t *testing.T) {
	const (
		serverID     = "server"
		resourceID   = "resource"
		credentialID = "credential"
	)
	graph := ingest.GraphData{
		Nodes: []ingest.Node{
			{ID: serverID, Kinds: []string{"MCPServer"}, Properties: map[string]any{
				"endpoint": "https://mcp.example/mcp", "transport": "http",
			}},
			{ID: resourceID, Kinds: []string{"MCPResource"}, Properties: map[string]any{"uri": "secret://one"}},
			{ID: credentialID, Kinds: []string{"Credential"}, Properties: map[string]any{
				"value":           "bearer-value",
				"value_hash":      common.HashCredentialValue("bearer-value"),
				"material_status": string(common.CredentialMaterialObserved),
				"auth_method":     string(common.AuthBearer),
			}},
		},
		Edges: []ingest.Edge{
			{Source: serverID, Target: resourceID, Kind: "PROVIDES_RESOURCE"},
			{Source: serverID, Target: resourceID, Kind: "PUBLIC_ACCESS_OBSERVED"},
		},
	}

	view := buildPlannerView(graph, nil, map[string]bool{}, false, false)
	if candidates := (credentialReachAction{}).Candidates(view); len(candidates) != 0 {
		t.Fatalf("candidates = %+v, want none after public access was proven", candidates)
	}
}

func TestA2ACredentialActionSkipsOnlyProvenAnonymousAgent(t *testing.T) {
	const (
		agentID      = "agent"
		credentialID = "credential"
	)
	credential := ingest.Node{ID: credentialID, Kinds: []string{"Credential"}, Properties: map[string]any{
		"value":           "compatible-bearer",
		"value_hash":      common.HashCredentialValue("compatible-bearer"),
		"material_status": string(common.CredentialMaterialObserved),
		"auth_method":     string(common.AuthBearer),
	}}
	for _, test := range []struct {
		name       string
		probeState string
		want       int
	}{
		{name: "anonymous access proven", probeState: a2acollector.A2AAuthProbeStatusAnonymousProtocolAccess, want: 0},
		{name: "authentication required", probeState: a2acollector.A2AAuthProbeStatusAuthenticationRequired, want: 1},
		{name: "probe unknown", probeState: a2acollector.A2AAuthProbeStatusUnknown, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := ingest.GraphData{Nodes: []ingest.Node{
				{ID: agentID, Kinds: []string{"A2AAgent"}, Properties: map[string]any{
					"url": "https://a2a.example", "auth_probe_status": test.probeState,
				}},
				credential,
			}}
			view := buildPlannerView(graph, nil, map[string]bool{}, false, false)
			if candidates := (a2aCredentialAction{}).Candidates(view); len(candidates) != test.want {
				t.Fatalf("candidates = %+v, want %d", candidates, test.want)
			}
		})
	}
}

func TestPlannerStopsOnWrappedCheckpointOrCleanupFailure(t *testing.T) {
	checkpointFailure := &checkpoint.CheckpointError{
		Phase: string(checkpoint.Durability), Committed: true, Err: errors.New("directory sync"),
	}
	for _, err := range []error{
		fmt.Errorf("action transition: %w", checkpointFailure),
		fmt.Errorf("cleanup: %w", errCleanupUnresolved),
	} {
		if !plannerMustStop(err) {
			t.Fatalf("planner did not stop for %v", err)
		}
	}
	if plannerMustStop(errors.New("independent collector failure")) {
		t.Error("ordinary independent failure should not stop forward planning")
	}
}

func TestOllamaEmbeddingCandidateRequiresDeepActiveMode(t *testing.T) {
	graph := ingest.GraphData{Nodes: []ingest.Node{{
		ID: "ollama-1", Kinds: []string{"OllamaInstance"},
		Properties: map[string]any{"endpoint": "http://127.0.0.1:11434"},
	}}}
	action := ollamaEmbeddingAction{}
	for _, test := range []struct {
		name          string
		deep, stealth bool
		want          int
	}{
		{name: "normal active", want: 0},
		{name: "deep active", deep: true, want: 1},
		{name: "deep stealth", deep: true, stealth: true, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := buildPlannerView(graph, nil, map[string]bool{}, test.deep, test.stealth)
			candidates := action.Candidates(view)
			if len(candidates) != test.want {
				t.Fatalf("candidates = %d, want %d", len(candidates), test.want)
			}
			if len(candidates) == 1 && candidates[0].ModuleID != "ollama.collect" {
				t.Fatalf("module = %q, want ollama.collect", candidates[0].ModuleID)
			}
		})
	}
}

func TestDeepServiceCollectionDoesNotRepeatBaseInventory(t *testing.T) {
	graph := ingest.GraphData{Nodes: []ingest.Node{
		{
			ID: "ollama-1", Kinds: []string{"OllamaInstance"},
			Properties: map[string]any{"endpoint": "http://127.0.0.1:11434"},
		},
		{
			ID: "qdrant-1", Kinds: []string{"QdrantInstance"},
			Properties: map[string]any{"endpoint": "http://127.0.0.1:6333"},
		},
	}}

	for _, test := range []struct {
		name                 string
		deep, stealth        bool
		wantOllamaBase       int
		wantQdrantCandidates int
		wantQdrantDeep       bool
	}{
		{name: "normal active", wantOllamaBase: 1, wantQdrantCandidates: 1},
		{name: "deep active", deep: true, wantQdrantCandidates: 1, wantQdrantDeep: true},
		{name: "deep stealth", deep: true, stealth: true, wantOllamaBase: 1, wantQdrantCandidates: 1, wantQdrantDeep: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := buildPlannerView(graph, nil, map[string]bool{}, test.deep, test.stealth)
			candidates := (serviceCollectAction{}).Candidates(view)
			var ollamaBase, qdrantCandidates int
			var qdrantDeep bool
			for _, candidate := range candidates {
				switch candidate.Inputs["service"] {
				case "ollama":
					ollamaBase++
				case "qdrant":
					qdrantCandidates++
					qdrantDeep = candidate.Inputs["deep"] == "true"
				}
			}
			if ollamaBase != test.wantOllamaBase ||
				qdrantCandidates != test.wantQdrantCandidates ||
				qdrantDeep != test.wantQdrantDeep {
				t.Fatalf(
					"candidates = %+v, want Ollama base=%d Qdrant=%d deep=%t",
					candidates, test.wantOllamaBase, test.wantQdrantCandidates, test.wantQdrantDeep,
				)
			}
		})
	}
}

type partialCollectorModule struct{}

func (*partialCollectorModule) ID() string            { return "test.partial.collect" }
func (*partialCollectorModule) Action() action.Action { return action.Collect }
func (*partialCollectorModule) Target() string        { return "test-partial" }
func (*partialCollectorModule) Description() string   { return "test partial collector" }
func (*partialCollectorModule) Version() string       { return "0.0.0-test" }
func (*partialCollectorModule) IsDestructive() bool   { return false }
func (*partialCollectorModule) Collect(context.Context, action.Target, action.CollectOptions) (*action.CollectResult, error) {
	return &action.CollectResult{
		IngestData: &ingest.IngestData{Graph: ingest.GraphData{Nodes: []ingest.Node{{
			ID: "retained", Kinds: []string{"MCPResource"}, Properties: map[string]any{},
		}}}},
		PartialErrors: []string{"endpoint returned 401"},
		Summary:       action.CollectSummary{PartialFailures: 1},
	}, nil
}

var registerPartialCollector sync.Once

func TestServiceCollectionRetainsPartialGraphButReturnsFailure(t *testing.T) {
	registerPartialCollector.Do(func() { module.Register(&partialCollectorModule{}) })
	result, err := (serviceCollectAction{}).Execute(context.Background(), Candidate{
		ModuleID: "test.partial.collect",
		Target:   action.Target{Kind: "url", Address: "https://service.example"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "partial failure") {
		t.Fatalf("error = %v, want structured partial failure", err)
	}
	if result.Outcome != "collection_partial" || len(result.Graph.Nodes) != 1 {
		t.Fatalf("partial result = %+v, want retained graph with partial outcome", result)
	}
	if len(result.InventoryOutcomes) != 1 || result.InventoryOutcomes[0].State != ingest.OutcomePartial {
		t.Fatalf("inventory outcomes = %+v, want one partial surface", result.InventoryOutcomes)
	}
	root := ingest.CollectorRootCoverageKey("scan")
	if result.InventoryOutcomes[0].ParentCoverageKey != root {
		t.Fatalf("inventory parent = %q, want scan root %q", result.InventoryOutcomes[0].ParentCoverageKey, root)
	}
	for _, domain := range result.Graph.Nodes[0].ObservationDomains {
		if domain == root {
			t.Fatal("service inventory fact was assigned to the shared scan root")
		}
	}
	if len(result.Graph.Nodes[0].ObservationDomains) != 1 ||
		result.Graph.Nodes[0].ObservationDomains[0] != result.InventoryOutcomes[0].CoverageKey {
		t.Fatalf("fact domains = %v, want inventory surface", result.Graph.Nodes[0].ObservationDomains)
	}
}

func TestA2AActionRequiresSuccessfulTargetOutcome(t *testing.T) {
	report := &ingest.CollectionReport{
		State: ingest.OutcomeFailed,
		Outcomes: []ingest.CollectionOutcome{{
			Collector: "a2a", State: ingest.OutcomeFailed, Error: "unauthorized",
		}},
	}
	if err := requireSuccessfulA2ACollection(report); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("error = %v, want failed target outcome", err)
	}
}

func TestPartiallyVerifiedCleanupRemainsIndeterminate(t *testing.T) {
	err := fmt.Errorf("secondary observation unavailable: %w", action.ErrRevertPartiallyVerified)
	if got := recoveryStatus(err); got != ingest.RecoveryIndeterminate {
		t.Fatalf("status = %q, want indeterminate", got)
	}
}

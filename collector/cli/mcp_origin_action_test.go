package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mcpcollector "github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestMCPOriginValidationCandidatesRequireObservedAnonymousStreamableHTTP(t *testing.T) {
	eligible := ingest.Node{
		ID: "mcp-server", Kinds: []string{"MCPServer"},
		Properties: map[string]any{
			"endpoint":               "https://mcp.example/mcp",
			"status":                 "reachable",
			"transport":              "http",
			"observed_transport":     mcpcollector.ObservedTransportStreamableHTTP,
			"protocol_version":       "2025-11-25",
			"observed_auth_method":   string(common.AuthNone),
			"observed_auth_evidence": common.AuthEvidenceAnonymousProbeSucceeded,
		},
		ObservationDomains: []string{"mcp:target:sha256:one"},
	}
	tests := []struct {
		name    string
		mutate  func(*ingest.Node)
		stealth bool
		want    int
	}{
		{name: "eligible", want: 1},
		{name: "stealth", stealth: true},
		{name: "legacy SSE", mutate: func(n *ingest.Node) { n.Properties["observed_transport"] = mcpcollector.ObservedTransportLegacySSE }},
		{name: "configured but unobserved", mutate: func(n *ingest.Node) { delete(n.Properties, "observed_transport") }},
		{name: "unreachable", mutate: func(n *ingest.Node) { n.Properties["status"] = "unreachable" }},
		{name: "authentication not reproducible", mutate: func(n *ingest.Node) { n.Properties["observed_auth_method"] = string(common.AuthBearer) }},
		{name: "query credential redacted", mutate: func(n *ingest.Node) { n.Properties["endpoint_query_redacted"] = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := eligible
			node.Properties = cloneAnyMap(eligible.Properties)
			if test.mutate != nil {
				test.mutate(&node)
			}
			view := buildPlannerView(
				ingest.GraphData{Nodes: []ingest.Node{node}}, nil, map[string]bool{}, false, test.stealth,
			)
			candidates := (mcpOriginValidationAction{}).Candidates(view)
			if len(candidates) != test.want {
				t.Fatalf("candidates = %+v, want %d", candidates, test.want)
			}
			if test.want == 1 {
				candidate := candidates[0]
				if candidate.Target.Address != "https://mcp.example/mcp" ||
					candidate.Inputs["protocol_version"] != "2025-11-25" ||
					candidate.CredentialID != "" || len(candidate.PathNodeIDs) != 1 {
					t.Fatalf("candidate = %+v", candidate)
				}
			}
		})
	}
}

func TestMCPOriginValidationExecuteStoresOnlyBoundedEvidence(t *testing.T) {
	const responseSecret = "SECRET-RESPONSE-BODY-MUST-NOT-PERSIST"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": request.ID,
			"result": map[string]any{"detail": responseSecret},
		})
	}))
	defer server.Close()

	candidate := Candidate{
		Key:    "origin-candidate",
		Target: action.Target{Kind: "url", Address: server.URL, Meta: map[string]string{"node_id": "mcp-server"}},
		Inputs: map[string]string{
			"action_id": "sha256:action", "server_id": "mcp-server",
			"protocol_version":    "2025-11-25",
			"observation_domains": "mcp:target:sha256:one",
		},
	}
	result, err := (mcpOriginValidationAction{timeout: time.Second}).Execute(
		context.Background(), candidate, nil,
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != "origin_validation_accepted" || len(result.Graph.Nodes) != 1 {
		t.Fatalf("result = %+v", result)
	}
	node := result.Graph.Nodes[0]
	if node.ID != "mcp-server" || node.Properties["origin_validation_status"] != "accepted" ||
		node.Properties["origin_validation_evidence"] != "matching_jsonrpc_response" ||
		node.Properties["origin_validation_http_status"] != http.StatusOK {
		t.Fatalf("node = %+v", node)
	}
	document, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, forbidden := range []string{responseSecret, "Mcp-Session-Id", `"result"`} {
		if strings.Contains(string(document), forbidden) {
			t.Fatalf("stored Origin evidence contains %q: %s", forbidden, document)
		}
	}
}

func TestMCPOriginValidationExecutePreservesIndeterminateOutcome(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	candidate := Candidate{
		Key:    "origin-candidate",
		Target: action.Target{Kind: "url", Address: server.URL, Meta: map[string]string{"node_id": "mcp-server"}},
		Inputs: map[string]string{"server_id": "mcp-server"},
	}
	result, err := (mcpOriginValidationAction{timeout: time.Second}).Execute(
		context.Background(), candidate, nil,
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != "origin_validation_indeterminate" ||
		result.Graph.Nodes[0].Properties["origin_validation_status"] != "indeterminate" {
		t.Fatalf("result = %+v", result)
	}
	if _, present := result.Graph.Nodes[0].Properties["origin_validation_evidence"]; present {
		t.Fatalf("ambiguous response acquired positive evidence: %+v", result.Graph.Nodes[0].Properties)
	}
}

func cloneAnyMap(values map[string]any) map[string]any {
	copy := make(map[string]any, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

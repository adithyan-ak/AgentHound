package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mcpcollector "github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const mcpOriginActionID = "mcp.origin.validate"

type mcpOriginValidationAction struct {
	insecure bool
	timeout  time.Duration
}

func (mcpOriginValidationAction) ID() string { return mcpOriginActionID }

func (a mcpOriginValidationAction) Candidates(view View) []Candidate {
	if view.Stealth {
		return nil
	}
	var candidates []Candidate
	seen := make(map[string]bool)
	for _, server := range view.Graph.Nodes {
		if seen[server.ID] || !containsPlannerString(server.Kinds, "MCPServer") {
			continue
		}
		endpoint := stringProperty(server.Properties, "endpoint")
		if endpoint == "" ||
			stringProperty(server.Properties, "status") != "reachable" ||
			stringProperty(server.Properties, "transport") != "http" ||
			stringProperty(server.Properties, "observed_transport") != mcpcollector.ObservedTransportStreamableHTTP ||
			server.Properties["endpoint_userinfo_redacted"] == true ||
			server.Properties["endpoint_query_redacted"] == true ||
			server.PropertySemantics != "" {
			continue
		}
		if !common.IsConfirmedAnonymousAccess(
			stringProperty(server.Properties, "observed_auth_method"),
			stringProperty(server.Properties, "observed_auth_evidence"),
		) {
			continue
		}
		encodedServer, err := json.Marshal(server)
		if err != nil {
			continue
		}
		seen[server.ID] = true
		candidate := Candidate{
			Priority: 4,
			ModuleID: a.ID(),
			Target: action.Target{Kind: "url", Address: endpoint, Meta: map[string]string{
				"url": endpoint, "node_id": server.ID,
			}},
			PathNodeIDs: []string{server.ID},
			Inputs: map[string]string{
				"server_id":        server.ID,
				"protocol_version": stringProperty(server.Properties, "protocol_version"),
				"server_node":      string(encodedServer),
			},
		}
		candidate.Key = candidateKey(a.ID(), endpoint, "", server.ID, view.Deep)
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (a mcpOriginValidationAction) Execute(
	ctx context.Context,
	candidate Candidate,
	_ Journal,
) (Result, error) {
	var server ingest.Node
	if err := json.Unmarshal([]byte(candidate.Inputs["server_node"]), &server); err != nil {
		return Result{}, fmt.Errorf("decode MCP Origin candidate node: %w", err)
	}
	serverID := candidate.Inputs["server_id"]
	if serverID == "" {
		serverID = candidate.Target.Meta["node_id"]
	}
	if server.ID != serverID || !containsPlannerString(server.Kinds, "MCPServer") ||
		server.PropertySemantics != "" || server.Properties == nil {
		return Result{}, fmt.Errorf("MCP Origin candidate node is not a complete MCPServer observation")
	}

	actionID := candidate.Inputs["action_id"]
	if actionID == "" {
		actionID = common.HashSHA256(candidate.Key)
	}
	probe := "agenthound-origin-" + strings.TrimPrefix(actionID, "sha256:")
	if len(probe) > 64 {
		probe = probe[:64]
	}
	validation, probeErr := mcpcollector.ProbeInvalidOrigin(
		ctx,
		candidate.Target.Address,
		candidate.Inputs["protocol_version"],
		probe,
		a.insecure,
		a.timeout,
	)

	properties := server.Properties
	properties["origin_validation_status"] = string(validation.Outcome)
	properties["origin_validation_probe_origin"] = mcpcollector.InvalidOriginProbeValue
	properties["origin_validation_cleanup_status"] = validation.CleanupStatus
	properties["origin_validation_action_id"] = actionID
	properties["origin_validation_observed_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	if validation.HTTPStatus > 0 {
		properties["origin_validation_http_status"] = validation.HTTPStatus
	}
	if validation.Evidence != "" {
		properties["origin_validation_evidence"] = validation.Evidence
	}
	server.Properties = properties
	graph := ingest.GraphData{Nodes: []ingest.Node{server}, Edges: []ingest.Edge{}}
	return Result{Graph: graph, Outcome: "origin_validation_" + string(validation.Outcome)}, probeErr
}

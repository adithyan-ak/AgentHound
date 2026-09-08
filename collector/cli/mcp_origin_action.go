package cli

import (
	"context"
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
	for _, server := range view.ByKind["MCPServer"] {
		endpoint := stringProperty(server.Properties, "endpoint")
		if endpoint == "" ||
			stringProperty(server.Properties, "status") != "reachable" ||
			stringProperty(server.Properties, "transport") != "http" ||
			stringProperty(server.Properties, "observed_transport") != mcpcollector.ObservedTransportStreamableHTTP ||
			server.Properties["endpoint_userinfo_redacted"] == true ||
			server.Properties["endpoint_query_redacted"] == true {
			continue
		}
		if !common.IsConfirmedAnonymousAccess(
			stringProperty(server.Properties, "observed_auth_method"),
			stringProperty(server.Properties, "observed_auth_evidence"),
		) {
			continue
		}
		candidate := Candidate{
			Priority: 4,
			ModuleID: a.ID(),
			Target: action.Target{Kind: "url", Address: endpoint, Meta: map[string]string{
				"url": endpoint, "node_id": server.ID,
			}},
			PathNodeIDs: []string{server.ID},
			Inputs: map[string]string{
				"server_id":           server.ID,
				"protocol_version":    stringProperty(server.Properties, "protocol_version"),
				"observation_domains": strings.Join(server.ObservationDomains, "\x1f"),
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

	properties := map[string]any{
		"origin_validation_status":         string(validation.Outcome),
		"origin_validation_probe_origin":   mcpcollector.InvalidOriginProbeValue,
		"origin_validation_cleanup_status": validation.CleanupStatus,
		"origin_validation_action_id":      actionID,
		"origin_validation_observed_at":    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if validation.HTTPStatus > 0 {
		properties["origin_validation_http_status"] = validation.HTTPStatus
	}
	if validation.Evidence != "" {
		properties["origin_validation_evidence"] = validation.Evidence
	}
	serverID := candidate.Inputs["server_id"]
	if serverID == "" {
		serverID = candidate.Target.Meta["node_id"]
	}
	graph := ingest.GraphData{
		Nodes: []ingest.Node{{
			ID: serverID, Kinds: []string{"MCPServer"}, Properties: properties,
			ObservationDomains: splitNonEmpty(candidate.Inputs["observation_domains"], "\x1f"),
		}},
		Edges: []ingest.Edge{},
	}
	return Result{Graph: graph, Outcome: "origin_validation_" + string(validation.Outcome)}, probeErr
}

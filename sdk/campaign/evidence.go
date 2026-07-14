package campaign

import (
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// OracleTypeDifferentialCredentialReach identifies the v1 read-only differential
// oracle (unauth control vs. authed probe of the exact predicted resource).
const OracleTypeDifferentialCredentialReach = "differential_credential_reach"

// evidenceRiskWeight is the risk_weight stamped on emitted evidence edges. Raw
// edges MUST carry a finite, non-negative risk_weight (ingest validator +
// traversal engine). Verification evidence is not itself a reach hop, so it uses
// the same low structural weight the collector uses for supporting edges.
const evidenceRiskWeight = 0.1

// Evidence property keys. Shared with the server re-correlation so both sides
// agree on the on-edge witness echo. All keys are canonical snake_case.
const (
	PropScenarioID          = "scenario_id"
	PropScenarioVersion     = "scenario_version"
	PropRunID               = "run_id"
	PropEngagementID        = "engagement_id"
	PropOracleType          = "oracle_type"
	PropOutcome             = "outcome"
	PropControlStage        = "control_stage"
	PropControlStatus       = "control_status"
	PropControlAddressed    = "control_resource_addressed"
	PropAuthedStage         = "authed_stage"
	PropAuthedStatus        = "authed_status"
	PropAuthedAddressed     = "authed_resource_addressed"
	PropVerifiedAt          = "verified_at"
	PropWitnessSchema       = "witness_schema_version"
	PropTopologyVersion     = "topology_normalization_version"
	PropPublicationRevision = "publication_revision"
	PropPredictedEdgeKind   = "predicted_edge_kind"
	PropAgentID             = "agent_id"
	PropAgentKind           = "agent_kind"
	PropCredentialID        = "credential_id"
	PropCredentialKind      = "credential_kind"
	PropCredentialValueHash = "credential_value_hash"
	PropCredentialMergeKey  = "credential_merge_key"
	PropServerID            = "server_id"
	PropServerKind          = "server_kind"
	PropResourceID          = "resource_id"
	PropResourceKind        = "resource_kind"
	PropResourceIdentity    = "resource_identity_input"
	PropEvidenceNodeIDs     = "evidence_node_ids"
	PropEvidenceNodeKinds   = "evidence_node_kinds"
	PropWitnessFingerprint  = "witness_fingerprint"
)

// Evidence is the collector-safe transport carried on an emitted evidence edge
// and echoed for server re-correlation. It NEVER carries the raw credential
// value — only its precomputed value_hash (via the witness) and the classified
// probe statuses.
type Evidence struct {
	ScenarioID       string      `json:"scenario_id"`
	ScenarioVersion  int         `json:"scenario_version"`
	RunID            string      `json:"run_id"`
	EngagementID     string      `json:"engagement_id"`
	OracleType       string      `json:"oracle_type"`
	Outcome          Outcome     `json:"outcome"`
	ControlStage     ProbeStage  `json:"control_stage"`
	ControlStatus    ProbeStatus `json:"control_status"`
	ControlAddressed bool        `json:"control_resource_addressed"`
	AuthedStage      ProbeStage  `json:"authed_stage"`
	AuthedStatus     ProbeStatus `json:"authed_status"`
	AuthedAddressed  bool        `json:"authed_resource_addressed"`
	VerifiedAt       string      `json:"verified_at"`
	Witness          Witness     `json:"witness"`
}

// edgeProperties builds the canonical edge property map for an emitted evidence
// edge, including the required risk_weight and the full stable witness echo.
func (e Evidence) edgeProperties(scanID string) map[string]any {
	w := e.Witness
	return map[string]any{
		"scan_id":               scanID,
		"last_seen":             time.Now().UTC().Format(time.RFC3339),
		"is_composite":          false,
		"confidence":            1.0,
		"risk_weight":           evidenceRiskWeight,
		PropScenarioID:          e.ScenarioID,
		PropScenarioVersion:     e.ScenarioVersion,
		PropRunID:               e.RunID,
		PropEngagementID:        e.EngagementID,
		PropOracleType:          e.OracleType,
		PropOutcome:             string(e.Outcome),
		PropControlStage:        string(e.ControlStage),
		PropControlStatus:       string(e.ControlStatus),
		PropControlAddressed:    e.ControlAddressed,
		PropAuthedStage:         string(e.AuthedStage),
		PropAuthedStatus:        string(e.AuthedStatus),
		PropAuthedAddressed:     e.AuthedAddressed,
		PropVerifiedAt:          e.VerifiedAt,
		PropWitnessSchema:       w.SchemaVersion,
		PropTopologyVersion:     w.TopologyNormalizationVersion,
		PropPublicationRevision: w.PublicationRevision,
		PropPredictedEdgeKind:   w.PredictedEdgeKind,
		PropAgentID:             w.AgentID,
		PropAgentKind:           w.AgentKind,
		PropCredentialID:        w.CredentialID,
		PropCredentialKind:      w.CredentialKind,
		PropCredentialValueHash: w.CredentialValueHash,
		PropCredentialMergeKey:  w.CredentialMergeKey,
		PropServerID:            w.ServerID,
		PropServerKind:          w.ServerKind,
		PropResourceID:          w.ResourceID,
		PropResourceKind:        w.ResourceKind,
		PropResourceIdentity:    w.ResourceIdentityInput,
		PropEvidenceNodeIDs:     append([]string{}, w.EvidenceNodeIDs...),
		PropEvidenceNodeKinds:   append([]string{}, w.EvidenceNodeKinds...),
		PropWitnessFingerprint:  w.Fingerprint(),
	}
}

// referenceNode builds a reference_only endpoint node that asserts only the
// node's ID and kind. Its properties are empty so ingest never authors or
// overwrites the live node's managed properties — the credential's real
// value_hash is read from the graph during re-correlation, not from here.
func referenceNode(id, kind string) ingest.Node {
	return ingest.Node{
		ID:                id,
		Kinds:             []string{kind},
		Properties:        map[string]any{},
		PropertySemantics: ingest.NodePropertySemanticsReferenceOnly,
	}
}

// EvidenceGraph returns the reference_only endpoint nodes and the single raw
// evidence edge for the classified outcome. Both endpoints are always included
// so the ingest validator's referenced-endpoint check passes. Outcomes that
// emit no edge (not_observed, indeterminate) return an empty graph — not_observed
// relies on the deterministic coverage domain to retire prior evidence.
//
// Observation domains are NOT set here; the envelope builder tags the whole
// graph with the deterministic coverage key.
func (e Evidence) EvidenceGraph(scanID string) ([]ingest.Node, []ingest.Edge) {
	kind, ok := e.Outcome.EdgeKind()
	if !ok {
		return nil, nil
	}
	w := e.Witness
	var sourceID, sourceKind string
	switch kind {
	case "CREDENTIAL_REACH_VERIFIED":
		sourceID, sourceKind = w.AgentID, "AgentInstance"
	case "PUBLIC_ACCESS_OBSERVED":
		sourceID, sourceKind = w.ServerID, "MCPServer"
	default:
		return nil, nil
	}
	nodes := []ingest.Node{
		referenceNode(sourceID, sourceKind),
		referenceNode(w.ResourceID, "MCPResource"),
	}
	edges := []ingest.Edge{{
		Source:     sourceID,
		Target:     w.ResourceID,
		Kind:       kind,
		SourceKind: sourceKind,
		TargetKind: "MCPResource",
		Properties: e.edgeProperties(scanID),
	}}
	return nodes, edges
}

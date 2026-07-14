package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

// findingFingerprint returns a stable 16-char hex fingerprint for a finding
// based on its edge kind and endpoints. Same logical finding across scans
// gets the same ID so triage workflows can track state.
func findingFingerprint(edgeKind, sourceID, targetID string) string {
	h := sha256.Sum256([]byte(edgeKind + "|" + sourceID + "|" + targetID))
	return hex.EncodeToString(h[:])[:16]
}

// findingMeta describes how a composite edge kind is presented as a finding.
// Description text is formatted separately with named source/target roles and
// detector evidence; a single positional placeholder cannot safely represent
// both actors (AH-UI-31).
type findingMeta struct {
	category string
	title    string
	owasp    []string
	atlas    []string
}

var findingsMeta = map[string]findingMeta{
	"CAN_EXFILTRATE_VIA": {
		category: "Data Exfiltration",
		title:    "Potential data exfiltration route",
		owasp:    []string{"MCP04", "ASI08", "ASI10"},
		// T0024 (AI inference-API extraction) deliberately excluded: this edge
		// models exfiltration through agent tool invocation, not the model.
		atlas: []string{"AML.T0086"},
	},
	"CAN_REACH": {
		category: "Transitive Access",
		title:    "Inferred agent-to-resource reachability",
		owasp:    []string{"MCP01", "ASI06"},
	},
	"CAN_REACH_CROSS_PROTOCOL": {
		category: "Cross-Protocol Correlation",
		title:    "Possible cross-protocol reachability",
		owasp:    []string{"MCP01", "ASI06"},
	},
	// Credential-chain presentation is split by evidence. Merely targeting a
	// Credential does not establish that usable material was observed.
	"CAN_REACH_CREDENTIAL_CHAIN_OBSERVED": {
		category: "Credential Exposure",
		title:    "Observed credential material is reachable",
		owasp:    []string{"MCP04", "ASI08"},
	},
	"CAN_REACH_CREDENTIAL_CHAIN_REFERENCE": {
		category: "Credential Reachability",
		title:    "Credential reference is reachable",
		owasp:    []string{"MCP04", "ASI08"},
	},
	"CAN_REACH_CREDENTIAL_REFERENCE": {
		category: "Credential Reachability",
		title:    "Credential node is reachable",
		owasp:    []string{"MCP04", "ASI08"},
	},
	"POISONED_DESCRIPTION": {
		category: "Prompt Injection",
		title:    "Suspicious tool-description patterns",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051", "AML.T0110"},
	},
	"SHADOWS": {
		category: "Tool Shadowing",
		title:    "Possible tool shadowing",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0110"},
	},
	"POISONED_INSTRUCTIONS": {
		category: "Instruction Poisoning",
		title:    "Suspicious instruction-file patterns",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051"},
	},
	"CAN_IMPERSONATE": {
		category: "Agent Impersonation",
		title:    "Possible agent impersonation",
		owasp:    []string{"MCP05", "ASI03"},
	},
	"CAN_EXECUTE": {
		category: "Remote Execution",
		title:    "Possible shell or code execution route",
		owasp:    []string{"MCP01", "ASI06"},
	},
	"HAS_ACCESS_TO": {
		category: "Resource Access",
		title:    "Inferred tool-to-resource access",
		owasp:    []string{"MCP04", "ASI08"},
	},
	"CONFUSED_DEPUTY": {
		category: "Authorization Confusion",
		title:    "Potential confused-deputy delegation",
		owasp:    []string{"ASI06", "MCP04"},
	},
	// CAN_REACH, HAS_ACCESS_TO, CAN_EXECUTE, CAN_IMPERSONATE, and
	// CONFUSED_DEPUTY are intentionally unmapped to ATLAS pending analyst
	// assignment -- AgentHound only ships techniques it has verified.
	"TAINTS": {
		category: "Cross-Tool Taint",
		title:    "Inferred cross-tool taint flow",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051"},
	},
	"IFC_VIOLATION": {
		category: "Information Flow Violation",
		title:    "Potential information-flow violation",
		owasp:    []string{"MCP05", "ASI08"},
		atlas:    []string{"AML.T0057", "AML.T0086"},
	},
	"POISONS_CONTEXT": {
		category: "Context Poisoning",
		title:    "Potential context-poisoning route",
		owasp:    []string{"MCP05", "ASI03"},
		atlas:    []string{"AML.T0051", "AML.T0110"},
	},
}

type findingActor struct {
	id   string
	name string
	kind string
}

type findingDescriptionContext struct {
	source                   findingActor
	target                   findingActor
	exfiltrationCapabilities []string
	confidence               float64
}

// formatFindingDescription names both endpoint roles explicitly. For
// exfiltration it reports the capability values that actually satisfied the
// detector instead of narrowing every route to outbound networking.
func formatFindingDescription(metaKey string, ctx findingDescriptionContext) string {
	source := formatFindingActor(ctx.source, "source")
	target := formatFindingActor(ctx.target, "target")
	switch metaKey {
	case "CAN_EXFILTRATE_VIA":
		if len(ctx.exfiltrationCapabilities) == 0 {
			return fmt.Sprintf("%s has inferred access to sensitive data, and %s matched the configured exfiltration-channel predicate; this is a potential route, not observed exfiltration", source, target)
		}
		return fmt.Sprintf("%s has inferred access to sensitive data, and %s matched the exfiltration-channel predicate via %s; this is a potential route, not observed exfiltration", source, target, strings.Join(ctx.exfiltrationCapabilities, ", "))
	case "CAN_REACH":
		return fmt.Sprintf("%s has an inferred transitive access path to %s", source, target)
	case "CAN_REACH_CROSS_PROTOCOL":
		return fmt.Sprintf("%s and the MCP path to %s correlate through a shared host; this %.0f%%-confidence hypothesis does not prove end-to-end invocation", source, target, ctx.confidence*100)
	case "CAN_REACH_CREDENTIAL_CHAIN_OBSERVED":
		return fmt.Sprintf("%s has a transitive path through a shared gateway to %s with observed usable material", source, target)
	case "CAN_REACH_CREDENTIAL_CHAIN_REFERENCE":
		return fmt.Sprintf("%s has a transitive path through a shared gateway to %s; this evidence contains no observed usable credential material", source, target)
	case "CAN_REACH_CREDENTIAL_REFERENCE":
		return fmt.Sprintf("%s has a transitive path to %s without credential-chain material evidence", source, target)
	case "POISONED_DESCRIPTION":
		return fmt.Sprintf("%s matched suspicious instruction patterns in its description", source)
	case "SHADOWS":
		return fmt.Sprintf("%s references %s by name from another server, matching the tool-shadowing heuristic", source, target)
	case "POISONED_INSTRUCTIONS":
		return fmt.Sprintf("%s matched suspicious instruction patterns", source)
	case "CAN_IMPERSONATE":
		return fmt.Sprintf("%s has skill-description similarity to %s above the impersonation heuristic threshold", source, target)
	case "CAN_EXECUTE":
		return fmt.Sprintf("%s was classified from tool metadata as exposing shell or code execution that may run on %s", source, target)
	case "HAS_ACCESS_TO":
		return fmt.Sprintf("%s has inferred access to %s", source, target)
	case "CONFUSED_DEPUTY":
		return fmt.Sprintf("%s delegates to higher-assurance %s, matching the confused-deputy heuristic", source, target)
	case "TAINTS":
		return fmt.Sprintf("%s shares schema with %s, creating an inferred untrusted-input flow", source, target)
	case "IFC_VIOLATION":
		return fmt.Sprintf("%s reaches sensitive sink %s across the configured information-flow boundary", source, target)
	case "POISONS_CONTEXT":
		return fmt.Sprintf("Content from %s may enter context used by high-capability %s", source, target)
	default:
		return fmt.Sprintf("Composite edge %s detected between %s and %s", metaKey, source, target)
	}
}

func formatFindingActor(actor findingActor, fallbackRole string) string {
	label := actor.name
	if label == "" {
		label = actor.id
	}
	role := map[string]string{
		"AgentInstance":   "agent",
		"A2AAgent":        "A2A agent",
		"MCPServer":       "MCP server",
		"MCPTool":         "tool",
		"MCPResource":     "resource",
		"Credential":      "credential",
		"Host":            "host",
		"Identity":        "identity",
		"InstructionFile": "instruction file",
	}[actor.kind]
	if role == "" {
		role = fallbackRole
	}
	return role + " " + label
}

const findingsQuery = `
MATCH (src)-[r]->(tgt)
WHERE r.is_composite = true
CALL {
  WITH r
  WITH coalesce(r.evidence_node_ids, []) AS witness_node_ids
  UNWIND CASE
    WHEN size(witness_node_ids) = 0 THEN []
    ELSE range(0, size(witness_node_ids) - 1)
  END AS witness_index
  OPTIONAL MATCH (witness_node)
  WHERE witness_node.objectid = witness_node_ids[witness_index]
  WITH witness_index, witness_node_ids[witness_index] AS expected_id, witness_node
  ORDER BY witness_index
  RETURN collect(
    CASE
      WHEN witness_node IS NULL
      THEN {id: expected_id, kinds: [], properties: {evidence_missing: true}}
      ELSE {
        id: witness_node.objectid,
        kinds: labels(witness_node),
        properties: properties(witness_node)
      }
    END
  ) AS detector_evidence_nodes
}
CALL {
  WITH r
  WITH coalesce(r.evidence_relationship_ids, []) AS witness_relationship_ids
  UNWIND CASE
    WHEN size(witness_relationship_ids) = 0 THEN []
    ELSE range(0, size(witness_relationship_ids) - 1)
  END AS witness_index
  OPTIONAL MATCH (witness_source)-[witness_relationship]->(witness_target)
  WHERE id(witness_relationship) = witness_relationship_ids[witness_index]
  WITH witness_index,
       witness_relationship_ids[witness_index] AS expected_id,
       witness_source,
       witness_relationship,
       witness_target
  ORDER BY witness_index
  RETURN collect(
    CASE
      WHEN witness_relationship IS NULL
      THEN {
        source: '',
        target: '',
        kind: '',
        properties: {evidence_missing: true, relationship_id: expected_id}
      }
      ELSE {
        source: witness_source.objectid,
        target: witness_target.objectid,
        kind: type(witness_relationship),
        properties: properties(witness_relationship)
      }
    END
  ) AS detector_evidence_edges
}
RETURN src.objectid AS source_id,
       src.name AS source_name,
       labels(src)[0] AS source_kind,
       tgt.objectid AS target_id,
       tgt.name AS target_name,
       labels(tgt)[0] AS target_kind,
       type(r) AS edge_kind,
       r.confidence AS confidence,
       r.cross_protocol AS cross_protocol,
       tgt.sensitivity AS target_sensitivity,
       r.source_collector AS source_collector,
       r.match_type AS match_type,
       tgt.capability_surface AS target_capabilities,
       tgt.merge_key AS target_merge_key,
       tgt.material_status AS target_material_status,
       tgt.exposure_status AS target_exposure_status,
       r.evidence_version AS evidence_version,
       r.reach_evidence_state AS reach_evidence_state,
       r.verified_scenario_id AS verified_scenario_id,
       r.verified_scenario_version AS verified_scenario_version,
       r.verified_run_id AS verified_run_id,
       r.verified_at AS verified_at,
       r.verified_oracle_type AS verified_oracle_type,
       r.verified_outcome AS verified_outcome,
       r.verified_control_stage AS verified_control_stage,
       r.verified_control_status AS verified_control_status,
       r.verified_control_resource_addressed AS verified_control_resource_addressed,
       r.verified_authed_stage AS verified_authed_stage,
       r.verified_authed_status AS verified_authed_status,
       r.verified_authed_resource_addressed AS verified_authed_resource_addressed,
       r.verified_cleanup_status AS verified_cleanup_status,
       detector_evidence_nodes AS exact_evidence_nodes,
       detector_evidence_edges AS exact_evidence_edges,
       r.evidence_synthetic_edge AS exact_evidence_synthetic_edge
ORDER BY r.confidence DESC`

// QueryFindings queries all composite edges and maps them to findings with severity.
func QueryFindings(ctx context.Context, db graph.GraphDB, severity string) ([]model.Finding, error) {
	rows, err := db.Query(ctx, findingsQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}

	var findings []model.Finding
	for _, row := range rows {
		edgeKind := stringVal(row, "edge_kind")
		sourceID := stringVal(row, "source_id")
		sourceName := stringVal(row, "source_name")
		sourceKind := stringVal(row, "source_kind")
		targetID := stringVal(row, "target_id")
		targetName := stringVal(row, "target_name")
		targetKind := stringVal(row, "target_kind")
		confidence := floatVal(row, "confidence")
		crossProtocol := boolVal(row, "cross_protocol")
		targetSensitivity := stringVal(row, "target_sensitivity")
		channels := matchedExfiltrationCapabilities(row)

		metaKey := edgeKind
		variant := model.FindingVariantDefault
		evidence := buildFindingEvidence(row, edgeKind, channels)
		var sev string
		switch {
		case isCredentialChainFinding(row):
			// A credential-chain edge is critical exposure only when its target
			// contains observed, usable material. Synthetic identities, hashes,
			// and redacted references stay medium and use non-exposure wording.
			if hasObservedUsableCredentialMaterial(row) {
				metaKey = "CAN_REACH_CREDENTIAL_CHAIN_OBSERVED"
				variant = model.FindingVariantCredentialObservedMaterial
				evidence.State = model.FindingEvidenceObserved
				sev = "critical"
			} else {
				metaKey = "CAN_REACH_CREDENTIAL_CHAIN_REFERENCE"
				variant = model.FindingVariantCredentialReference
				evidence.State = model.FindingEvidenceReferenceOnly
				sev = "medium"
			}
		case edgeKind == "CAN_REACH" && targetKind == "Credential":
			// Target type alone is not credential-chain or exposure evidence.
			metaKey = "CAN_REACH_CREDENTIAL_REFERENCE"
			variant = model.FindingVariantCredentialNodeReference
			evidence.State = model.FindingEvidenceReferenceOnly
			sev = "medium"
		case edgeKind == "CAN_REACH" && crossProtocol:
			metaKey = "CAN_REACH_CROSS_PROTOCOL"
			variant = model.FindingVariantCrossProtocolHostCorrelation
			evidence.State = model.FindingEvidenceHypothesis
			evidence.Correlation = "shared_host"
			sev = classifySeverity(edgeKind, true, confidence, targetSensitivity)
		default:
			sev = classifySeverity(edgeKind, crossProtocol, confidence, targetSensitivity)
		}
		// Campaign verification upgrade: when the CAN_REACH processor re-correlated
		// a CREDENTIAL_REACH_VERIFIED edge, the composite edge carries
		// reach_evidence_state=verified and confidence was raised to 1.0. This
		// upgrades the SAME finding's evidence state (and, via the higher
		// confidence already read above, its severity) — no second finding.
		if stringVal(row, "reach_evidence_state") == string(model.FindingEvidenceVerified) {
			evidence.State = model.FindingEvidenceVerified
		}
		if severity != "" && sev != severity {
			continue
		}

		meta, ok := findingsMeta[metaKey]
		if !ok {
			meta = findingMeta{
				category: "Other",
				title:    edgeKind + " finding",
			}
		}

		description := formatFindingDescription(metaKey, findingDescriptionContext{
			source: findingActor{
				id: sourceID, name: sourceName, kind: sourceKind,
			},
			target: findingActor{
				id: targetID, name: targetName, kind: targetKind,
			},
			exfiltrationCapabilities: channels,
			confidence:               confidence,
		})

		findings = append(findings, model.Finding{
			ID:            findingFingerprint(edgeKind, sourceID, targetID),
			Severity:      sev,
			Category:      meta.category,
			Title:         meta.title,
			Description:   description,
			EdgeKind:      edgeKind,
			SourceID:      sourceID,
			SourceName:    sourceName,
			SourceKind:    sourceKind,
			TargetID:      targetID,
			TargetName:    targetName,
			TargetKind:    targetKind,
			Confidence:    confidence,
			Variant:       variant,
			Evidence:      evidence,
			ExactEvidence: exactFindingEvidenceFromRow(row),
			OWASPMap:      append([]string{}, meta.owasp...),
			ATLASMap:      append([]string{}, meta.atlas...),
		})
	}

	return findings, nil
}

func isCredentialChainFinding(row map[string]any) bool {
	return stringVal(row, "edge_kind") == "CAN_REACH" &&
		stringVal(row, "target_kind") == "Credential" &&
		stringVal(row, "source_collector") == "cross_service_credential_chain"
}

// hasObservedUsableCredentialMaterial requires the canonical evidence contract.
func hasObservedUsableCredentialMaterial(row map[string]any) bool {
	materialStatus := stringVal(row, "target_material_status")
	exposureStatus := stringVal(row, "target_exposure_status")
	return materialStatus == string(common.CredentialMaterialObserved) &&
		exposureStatus == string(common.CredentialExposureExposed) &&
		stringVal(row, "target_merge_key") == "value_hash"
}

var exfiltrationCapabilityOrder = []string{
	"email_send",
	"network_outbound",
	"file_write",
	"auto_fetch_render",
	"allowlisted_proxy",
}

func matchedExfiltrationCapabilities(row map[string]any) []string {
	caps := stringSliceVal(row, "target_capabilities")
	if len(caps) == 0 {
		return nil
	}
	present := make(map[string]bool, len(caps))
	for _, cap := range caps {
		present[cap] = true
	}
	var matched []string
	for _, cap := range exfiltrationCapabilityOrder {
		if present[cap] {
			matched = append(matched, cap)
		}
	}
	return matched
}

func buildFindingEvidence(
	row map[string]any,
	edgeKind string,
	channels []string,
) model.FindingEvidence {
	detector := stringVal(row, "source_collector")
	state := model.FindingEvidenceUnknown
	if detector != "" {
		state = model.FindingEvidenceInferred
		if edgeKind == "POISONED_DESCRIPTION" || edgeKind == "POISONED_INSTRUCTIONS" {
			state = model.FindingEvidenceObserved
		}
	}
	materialStatus := stringVal(row, "target_material_status")
	exposureStatus := stringVal(row, "target_exposure_status")
	if stringVal(row, "target_kind") == "Credential" {
		if materialStatus == "" {
			materialStatus = "unknown"
		}
		if exposureStatus == "" {
			exposureStatus = "unknown"
		}
	}
	return model.FindingEvidence{
		State:          state,
		Detector:       detector,
		MatchType:      stringVal(row, "match_type"),
		Channels:       append([]string{}, channels...),
		MaterialStatus: materialStatus,
		ExposureStatus: exposureStatus,
		Verification:   buildFindingVerification(row),
	}
}

func buildFindingVerification(row map[string]any) *model.FindingVerification {
	if stringVal(row, "reach_evidence_state") != string(model.FindingEvidenceVerified) {
		return nil
	}
	return &model.FindingVerification{
		ScenarioID:               stringVal(row, "verified_scenario_id"),
		ScenarioVersion:          intVal(row, "verified_scenario_version"),
		CampaignRunID:            stringVal(row, "verified_run_id"),
		VerifiedAt:               stringVal(row, "verified_at"),
		OracleType:               stringVal(row, "verified_oracle_type"),
		Outcome:                  stringVal(row, "verified_outcome"),
		ControlStage:             stringVal(row, "verified_control_stage"),
		ControlStatus:            stringVal(row, "verified_control_status"),
		ControlResourceAddressed: boolVal(row, "verified_control_resource_addressed"),
		AuthedStage:              stringVal(row, "verified_authed_stage"),
		AuthedStatus:             stringVal(row, "verified_authed_status"),
		AuthedResourceAddressed:  boolVal(row, "verified_authed_resource_addressed"),
		CleanupStatus:            stringVal(row, "verified_cleanup_status"),
	}
}

func exactFindingEvidenceFromRow(row map[string]any) *model.ExactFindingEvidence {
	version := intVal(row, "evidence_version")
	if version <= 0 {
		return nil
	}
	exact := &model.ExactFindingEvidence{
		Version: version,
		Nodes:   []model.ExactFindingEvidenceNode{},
		Edges:   []model.ExactFindingEvidenceEdge{},
		Reasons: []string{},
	}
	nodeIDs := make(map[string]bool)
	rawNodes, nodesOK := anySlice(row["exact_evidence_nodes"])
	if !nodesOK {
		exact.Reasons = append(exact.Reasons, "nodes_not_an_array")
	}
	for i, raw := range rawNodes {
		node, ok := raw.(map[string]any)
		if !ok {
			exact.Reasons = append(exact.Reasons, fmt.Sprintf("node_%d_not_an_object", i))
			continue
		}
		id := stringVal(node, "id")
		if id == "" {
			exact.Reasons = append(exact.Reasons, fmt.Sprintf("node_%d_missing_id", i))
			continue
		}
		properties, _ := node["properties"].(map[string]any)
		if properties == nil {
			properties = map[string]any{}
		}
		if boolFromAny(properties["evidence_missing"]) {
			exact.Reasons = append(exact.Reasons, "detector_node_missing:"+id)
		}
		if nodeIDs[id] {
			continue
		}
		nodeIDs[id] = true
		exact.Nodes = append(exact.Nodes, model.ExactFindingEvidenceNode{
			ID:         id,
			Kinds:      stringSliceVal(node, "kinds"),
			Properties: properties,
		})
	}
	if len(exact.Nodes) == 0 {
		exact.Reasons = append(exact.Reasons, "no_detector_nodes")
	}

	rawEdges, edgesOK := anySlice(row["exact_evidence_edges"])
	if !edgesOK {
		exact.Reasons = append(exact.Reasons, "edges_not_an_array")
	}
	for i, raw := range rawEdges {
		edge, ok := raw.(map[string]any)
		if !ok {
			exact.Reasons = append(exact.Reasons, fmt.Sprintf("edge_%d_not_an_object", i))
			continue
		}
		source := stringVal(edge, "source")
		target := stringVal(edge, "target")
		kind := stringVal(edge, "kind")
		properties, _ := edge["properties"].(map[string]any)
		if properties == nil {
			properties = map[string]any{}
		}
		if boolFromAny(properties["evidence_missing"]) ||
			source == "" || target == "" || kind == "" {
			exact.Reasons = append(exact.Reasons, fmt.Sprintf("detector_edge_%d_missing", i))
			continue
		}
		exact.Edges = append(exact.Edges, model.ExactFindingEvidenceEdge{
			Source: source, Target: target, Kind: kind,
			Properties: publicWitnessRelationshipProperties(properties),
		})
	}

	synthetic := stringSliceVal(row, "exact_evidence_synthetic_edge")
	if len(synthetic) > 0 {
		if len(synthetic) < 6 ||
			synthetic[0] == "" || synthetic[1] == "" || synthetic[2] == "" {
			exact.Reasons = append(exact.Reasons, "synthetic_edge_malformed")
		} else {
			exact.Edges = append(exact.Edges, model.ExactFindingEvidenceEdge{
				Source: synthetic[0],
				Target: synthetic[1],
				Kind:   synthetic[2],
				Properties: map[string]any{
					"is_synthetic":     true,
					"provenance_type":  synthetic[3],
					"provenance_basis": synthetic[4],
					"source_collector": synthetic[5],
				},
				Synthetic: true,
				Provenance: map[string]any{
					"type":             synthetic[3],
					"basis":            synthetic[4],
					"source_collector": synthetic[5],
				},
			})
		}
	}
	for i, edge := range exact.Edges {
		if !nodeIDs[edge.Source] || !nodeIDs[edge.Target] {
			exact.Reasons = append(
				exact.Reasons,
				fmt.Sprintf("edge_%d_endpoint_missing", i),
			)
		}
	}
	exact.Reasons = sortedUnique(exact.Reasons)
	exact.Complete = len(exact.Reasons) == 0
	return exact
}

func anySlice(value any) ([]any, bool) {
	if value == nil {
		return []any{}, true
	}
	values, ok := value.([]any)
	if !ok {
		return []any{}, false
	}
	return values, true
}

func boolFromAny(value any) bool {
	enabled, _ := value.(bool)
	return enabled
}

func publicWitnessRelationshipProperties(properties map[string]any) map[string]any {
	out := make(map[string]any, len(properties))
	for key, value := range properties {
		switch key {
		case "evidence_version",
			"evidence_node_ids",
			"evidence_relationship_ids",
			"evidence_synthetic_edge":
			continue
		default:
			out[key] = value
		}
	}
	return out
}

func classifySeverity(edgeKind string, crossProtocol bool, confidence float64, targetSensitivity string) string {
	switch edgeKind {
	case "CAN_EXFILTRATE_VIA":
		return "critical"
	case "CAN_REACH":
		if crossProtocol {
			// A cross-protocol edge is a shared-host correlation hypothesis,
			// not proof that the A2A actor can invoke the MCP path end to end.
			// Preserve prioritization for sensitive targets without assigning
			// a critical verdict to a 50%-confidence correlation.
			if targetSensitivity == "critical" || targetSensitivity == "high" {
				return "high"
			}
			return "medium"
		}
		if confidence >= 0.8 && targetSensitivity == "critical" {
			return "critical"
		}
		if targetSensitivity == "high" {
			return "high"
		}
		return "medium"
	case "POISONED_DESCRIPTION", "SHADOWS", "POISONED_INSTRUCTIONS",
		"CONFUSED_DEPUTY", "IFC_VIOLATION", "POISONS_CONTEXT":
		return "high"
	case "CAN_IMPERSONATE", "CAN_EXECUTE", "HAS_ACCESS_TO", "TAINTS":
		return "medium"
	default:
		return "low"
	}
}

func intVal(row map[string]any, key string) int {
	switch value := row[key].(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func stringVal(row map[string]any, key string) string {
	v, ok := row[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func floatVal(row map[string]any, key string) float64 {
	v, ok := row[key]
	if !ok || v == nil {
		return 0
	}
	switch f := v.(type) {
	case float64:
		return f
	case int64:
		return float64(f)
	default:
		return 0
	}
}

func boolVal(row map[string]any, key string) bool {
	v, ok := row[key]
	if !ok || v == nil {
		return false
	}
	b, _ := v.(bool)
	return b
}

func stringSliceVal(row map[string]any, key string) []string {
	switch values := row[key].(type) {
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// witnessExportQuery selects credential-gated CAN_REACH predictions to an MCP
// resource and the sanitized identity tuple needed to build a stable witness.
// It deliberately returns only content-hashed node IDs, the credential
// value_hash + merge_key, and the resource URI (the identity input that binds to
// the resource node ID) — never Neo4j relationship IDs and never arbitrary node
// properties.
//
// The predicted edge is the credential-chain CAN_REACH (e.via_credential set)
// whose evidence path includes a runnable credential. The witness ServerID is
// the resource's PROVIDING server, so ComputeNodeID("MCPResource", ServerID,
// ResourceURI) == ResourceID and the collector can connect there to read it.
const witnessExportQuery = `
MATCH (a:AgentInstance)-[e:CAN_REACH]->(r:MCPResource)
WHERE e.is_composite = true
  AND e.via_credential IS NOT NULL
  AND coalesce(r.is_template, false) = false
MATCH (sr:MCPServer)-[:PROVIDES_RESOURCE]->(r)
WHERE toLower(coalesce(sr.transport, '')) = 'http'
MATCH (c:Credential)
WHERE c.objectid IN e.evidence_node_ids
  AND c.merge_key = 'value_hash'
  AND coalesce(c.value_hash, '') <> ''
WITH a, e, r, sr, c, e.evidence_node_ids AS evidence_node_ids
CALL {
  WITH evidence_node_ids
  UNWIND range(0, size(evidence_node_ids) - 1) AS evidence_index
  OPTIONAL MATCH (evidence_node)
  WHERE evidence_node.objectid = evidence_node_ids[evidence_index]
  WITH evidence_index, labels(evidence_node) AS evidence_labels
  ORDER BY evidence_index
  RETURN collect(evidence_labels) AS evidence_node_labels
}
RETURN a.objectid AS agent_id,
       r.objectid AS resource_id,
       r.uri AS resource_uri,
       c.objectid AS credential_id,
       c.value_hash AS credential_value_hash,
       c.merge_key AS credential_merge_key,
       sr.objectid AS server_id,
       sr.transport AS server_transport,
       evidence_node_ids,
       evidence_node_labels`

// BuildWitness exports a stable, sanitized witness for the predicted CAN_REACH
// finding identified by findingID (its 16-char fingerprint). The returned
// witness is structure-validated (its resource_uri binds to the resource node
// ID) but its PublicationRevision is left unset (0): the caller runs BuildWitness
// inside a guarded projection read and stamps the revision from the read's
// identity, then runs the full Validate. So a tampered export cannot be produced
// here, and the revision always matches the projection actually read.
//
// This deliberately does NOT reuse the finding-detail exporter: that copies
// arbitrary node properties, which would leak sensitive data into the witness.
func BuildWitness(
	ctx context.Context,
	db graph.GraphDB,
	findingID string,
) (*campaign.Witness, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, errors.New("witness export: finding id is required")
	}
	rows, err := db.Query(ctx, witnessExportQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("witness export query: %w", err)
	}
	for _, row := range rows {
		agentID := stringVal(row, "agent_id")
		resourceID := stringVal(row, "resource_id")
		if agentID == "" || resourceID == "" {
			continue
		}
		if findingFingerprint("CAN_REACH", agentID, resourceID) != findingID {
			continue
		}
		serverID := stringVal(row, "server_id")
		credentialID := stringVal(row, "credential_id")
		if strings.ToLower(stringVal(row, "server_transport")) != "http" {
			continue
		}
		evidenceNodeIDs := stringSliceVal(row, "evidence_node_ids")
		evidenceNodeKinds, err := normalizedEvidenceNodeKinds(row["evidence_node_labels"])
		if err != nil {
			return nil, fmt.Errorf("witness export: invalid current evidence topology: %w", err)
		}
		witness := &campaign.Witness{
			SchemaVersion:                campaign.WitnessSchemaVersion,
			TopologyNormalizationVersion: campaign.WitnessTopologyNormalizationVersion,
			PredictedEdgeKind:            campaign.PredictedEdgeKindCanReach,
			AgentID:                      agentID,
			AgentKind:                    "AgentInstance",
			CredentialID:                 credentialID,
			CredentialKind:               "Credential",
			CredentialValueHash:          stringVal(row, "credential_value_hash"),
			CredentialMergeKey:           stringVal(row, "credential_merge_key"),
			ServerID:                     serverID,
			ServerKind:                   "MCPServer",
			ResourceID:                   resourceID,
			ResourceKind:                 "MCPResource",
			ResourceIdentityInput:        stringVal(row, "resource_uri"),
			EvidenceNodeIDs:              evidenceNodeIDs,
			EvidenceNodeKinds:            evidenceNodeKinds,
		}
		if err := witness.ValidateStructure(); err != nil {
			return nil, fmt.Errorf(
				"witness export: built witness failed self-validation "+
					"(resource_uri does not bind to the resource node id): %w", err)
		}
		return witness, nil
	}
	return nil, fmt.Errorf(
		"witness export: no runnable credential-gated CAN_REACH prediction matches finding %q", findingID)
}

func normalizedEvidenceNodeKinds(value any) ([]string, error) {
	rawNodes, ok := anySlice(value)
	if !ok {
		return nil, errors.New("evidence node labels are not an array")
	}
	kinds := make([]string, 0, len(rawNodes))
	for i, raw := range rawNodes {
		labels := stringSliceFromAny(raw)
		concrete := normalizedConcreteKind(labels)
		if concrete == "" {
			return nil, fmt.Errorf("evidence node %d has no unique public concrete kind", i)
		}
		kinds = append(kinds, concrete)
	}
	return kinds, nil
}

func normalizedConcreteKind(labels []string) string {
	concrete := ""
	seen := make(map[string]bool, len(labels))
	for _, label := range labels {
		if seen[label] || !ingest.AllowedNodeKinds[label] {
			return ""
		}
		seen[label] = true
		if ingest.UmbrellaLabels[label] {
			continue
		}
		if concrete != "" {
			return ""
		}
		concrete = label
	}
	if concrete == "" {
		return ""
	}
	for label := range seen {
		if label != concrete && !ingest.UmbrellaCompanions[concrete][label] {
			return ""
		}
	}
	return concrete
}

func stringSliceFromAny(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil
			}
			result = append(result, text)
		}
		return result
	default:
		return nil
	}
}

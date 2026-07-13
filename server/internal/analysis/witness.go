package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
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
MATCH (c:Credential)
WHERE c.objectid IN e.evidence_node_ids
  AND c.merge_key = 'value_hash'
  AND coalesce(c.value_hash, '') <> ''
RETURN a.objectid AS agent_id,
       r.objectid AS resource_id,
       r.uri AS resource_uri,
       c.objectid AS credential_id,
       c.value_hash AS credential_value_hash,
       c.merge_key AS credential_merge_key,
       sr.objectid AS server_id`

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
		witness := &campaign.Witness{
			SchemaVersion:       campaign.WitnessSchemaVersion,
			PredictedEdgeKind:   campaign.PredictedEdgeKindCanReach,
			CredentialID:        credentialID,
			CredentialValueHash: stringVal(row, "credential_value_hash"),
			CredentialMergeKey:  stringVal(row, "credential_merge_key"),
			ServerID:            serverID,
			ResourceID:          resourceID,
			ResourceURI:         stringVal(row, "resource_uri"),
			PathTopology: []campaign.PathHop{
				{NodeID: agentID, Kind: "AgentInstance"},
				{NodeID: serverID, Kind: "MCPServer"},
				{NodeID: credentialID, Kind: "Credential"},
				{NodeID: resourceID, Kind: "MCPResource"},
			},
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

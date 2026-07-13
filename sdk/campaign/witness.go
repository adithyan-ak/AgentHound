package campaign

import (
	"errors"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// WitnessSchemaVersion is the current witness wire schema. The server stamps it
// on export and both the collector (Validate) and the server re-correlation
// reject any other value, so a witness produced by an incompatible build is
// rejected rather than silently misinterpreted (stale-schema rejection).
const WitnessSchemaVersion = 1

// PredictedEdgeKindCanReach is the only predicted edge the v1 differential
// credential-reach scenario upgrades. Credential-chain predictions surface as a
// CAN_REACH edge in the live graph, so the witness names CAN_REACH.
const PredictedEdgeKindCanReach = "CAN_REACH"

// CredentialMergeKeyValueHash is the only runnable credential merge key. A
// synthetic identity credential (merge_key="identity", e.g. a masked upstream
// LiteLLM key) has no observable raw material, so it can never be hash-matched
// and is not a runnable target (a precondition failure, not indeterminate).
const CredentialMergeKeyValueHash = "value_hash"

// PathHop is one ordered node in the predicted reach path. Only the stable
// content-hashed node ID and its concrete kind are carried; no node properties.
type PathHop struct {
	NodeID string `json:"node_id"`
	Kind   string `json:"kind"`
}

// Witness is the STABLE, SANITIZED logical artifact the server exports for a
// predicted CAN_REACH / credential-chain finding and the collector passes back
// as observed evidence. It is a content-addressed tuple — node IDs, the
// credential value_hash + merge_key, the predicted edge kind, the ordered path
// topology, and the publication/schema revision. It deliberately contains NO
// Neo4j relationship IDs (composite edges are recreated every epoch), NO
// arbitrary node properties, and NO secrets.
//
// ResourceURI is the sole free-text field and is NOT arbitrary metadata: it is
// the identity input from which ResourceID is derived
// (ComputeNodeID("MCPResource", ServerID, ResourceURI)). Validate enforces that
// binding so a tampered URI cannot point the read probe at a different resource
// than the one whose ID is being verified.
type Witness struct {
	SchemaVersion       int    `json:"schema_version"`
	PublicationRevision int    `json:"publication_revision"`
	PredictedEdgeKind   string `json:"predicted_edge_kind"`

	CredentialID        string `json:"credential_id"`
	CredentialValueHash string `json:"credential_value_hash"`
	CredentialMergeKey  string `json:"credential_merge_key"`

	ServerID    string `json:"server_id"`
	ResourceID  string `json:"resource_id"`
	ResourceURI string `json:"resource_uri"`

	PathTopology []PathHop `json:"path_topology"`
}

// Validate performs full structural + integrity checks, including the
// publication revision. It is the collector-side gate before any probe runs. It
// does NOT prove the prediction still holds — that is the server's
// re-correlation job on ingest.
func (w Witness) Validate() error {
	if w.PublicationRevision < 1 {
		return errors.New("witness publication_revision must be a positive integer")
	}
	return w.ValidateStructure()
}

// ValidateStructure runs every check Validate does except the publication
// revision. The server builds a witness from the graph and only knows the
// revision after the guarded projection read, so it validates structure during
// the build and the full Validate (revision included) afterward.
func (w Witness) ValidateStructure() error {
	if w.SchemaVersion != WitnessSchemaVersion {
		return fmt.Errorf(
			"witness schema version %d is not supported (want %d): stale or forged export",
			w.SchemaVersion, WitnessSchemaVersion,
		)
	}
	if w.PredictedEdgeKind != PredictedEdgeKindCanReach {
		return fmt.Errorf(
			"witness predicted_edge_kind %q is not runnable (want %q)",
			w.PredictedEdgeKind, PredictedEdgeKindCanReach,
		)
	}
	if strings.TrimSpace(w.CredentialID) == "" {
		return errors.New("witness credential_id must not be empty")
	}
	if strings.TrimSpace(w.CredentialValueHash) == "" {
		return errors.New("witness credential_value_hash must not be empty")
	}
	if w.CredentialMergeKey != CredentialMergeKeyValueHash {
		return fmt.Errorf(
			"witness credential_merge_key %q is not runnable (want %q): "+
				"hash-only / synthetic-identity credentials cannot be hash-matched",
			w.CredentialMergeKey, CredentialMergeKeyValueHash,
		)
	}
	if strings.TrimSpace(w.ServerID) == "" {
		return errors.New("witness server_id must not be empty")
	}
	if strings.TrimSpace(w.ResourceID) == "" {
		return errors.New("witness resource_id must not be empty")
	}
	if strings.TrimSpace(w.ResourceURI) == "" {
		return errors.New("witness resource_uri must not be empty")
	}
	if bound := ingest.ComputeNodeID("MCPResource", w.ServerID, w.ResourceURI); bound != w.ResourceID {
		return fmt.Errorf(
			"witness resource_id does not bind to (server_id, resource_uri): forged or mismatched witness",
		)
	}
	if len(w.PathTopology) == 0 {
		return errors.New("witness path_topology must not be empty")
	}
	sawCredential, sawResource := false, false
	for i, hop := range w.PathTopology {
		if strings.TrimSpace(hop.NodeID) == "" || strings.TrimSpace(hop.Kind) == "" {
			return fmt.Errorf("witness path_topology[%d] requires node_id and kind", i)
		}
		if hop.NodeID == w.CredentialID {
			sawCredential = true
		}
		if hop.NodeID == w.ResourceID {
			sawResource = true
		}
	}
	if !sawCredential {
		return errors.New("witness path_topology must include the credential node")
	}
	if !sawResource {
		return errors.New("witness path_topology must include the resource node")
	}
	return nil
}

// Fingerprint is a stable 64-char hex digest of the whole witness tuple. It is
// stamped on the evidence edge so any downstream tamper (a field changed after
// export) is detectable by recomputing the fingerprint over the echoed fields.
func (w Witness) Fingerprint() string {
	hash, err := common.CanonicalJSONHash(w)
	if err != nil {
		// CanonicalJSONHash only fails on unmarshalable types; Witness is all
		// strings/ints, so this is unreachable in practice.
		return ""
	}
	return hash
}

// PathTopologyNodeIDs returns the ordered node IDs, for edge serialization and
// server re-correlation.
func (w Witness) PathTopologyNodeIDs() []string {
	ids := make([]string, len(w.PathTopology))
	for i, hop := range w.PathTopology {
		ids[i] = hop.NodeID
	}
	return ids
}

// PathTopologyKinds returns the ordered node kinds, parallel to
// PathTopologyNodeIDs.
func (w Witness) PathTopologyKinds() []string {
	kinds := make([]string, len(w.PathTopology))
	for i, hop := range w.PathTopology {
		kinds[i] = hop.Kind
	}
	return kinds
}

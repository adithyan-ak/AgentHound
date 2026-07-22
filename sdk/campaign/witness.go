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
const WitnessSchemaVersion = 3

// WitnessTopologyNormalizationVersion identifies the deterministic concrete-kind
// normalization used for the ordered current CAN_REACH evidence topology.
const WitnessTopologyNormalizationVersion = 1

// PredictedEdgeKindCanReach is the only predicted edge the v1 differential
// credential-reach scenario upgrades. Credential-chain predictions surface as a
// CAN_REACH edge in the live graph, so the witness names CAN_REACH.
const PredictedEdgeKindCanReach = "CAN_REACH"

// CredentialMergeKeyValueHash is the only runnable credential merge key. A
// synthetic identity credential (merge_key="identity", e.g. a masked upstream
// LiteLLM key) has no observable raw material, so it can never be hash-matched
// and is not a runnable target (a precondition failure, not indeterminate).
const CredentialMergeKeyValueHash = "value_hash"

// Witness is the STABLE, SANITIZED logical artifact the server exports for a
// predicted CAN_REACH / credential-chain finding and the collector passes back
// as observed evidence. It is a content-addressed tuple — node IDs, the
// credential value_hash + merge_key, the predicted edge kind, the ordered path
// topology, and the publication/schema revision. It deliberately contains NO
// Neo4j relationship IDs (composite edges are recreated every epoch), NO
// arbitrary node properties, and NO secrets.
//
// ResourceIdentityInput is the sole free-text field and is NOT arbitrary
// metadata: it is the identity input from which ResourceID is derived.
// ServerIdentityID is the endpoint-derived, pre-scope content ID. Validate uses
// it with the opaque service scope to bind both scoped graph IDs. The HTTP
// endpoint remains out-of-band and never enters this artifact.
type Witness struct {
	SchemaVersion                int    `json:"schema_version"`
	TopologyNormalizationVersion int    `json:"topology_normalization_version"`
	PublicationRevision          int    `json:"publication_revision"`
	PredictedEdgeKind            string `json:"predicted_edge_kind"`

	AgentID   string `json:"agent_id"`
	AgentKind string `json:"agent_kind"`

	CredentialID        string `json:"credential_id"`
	CredentialKind      string `json:"credential_kind"`
	CredentialValueHash string `json:"credential_value_hash"`
	CredentialMergeKey  string `json:"credential_merge_key"`

	ServerID         string `json:"server_id"`
	ServerKind       string `json:"server_kind"`
	ServerIdentityID string `json:"server_identity_id"`

	ServiceScope   ingest.IdentityScope `json:"service_scope"`
	ServiceScopeID string               `json:"service_scope_id"`

	ResourceID            string `json:"resource_id"`
	ResourceKind          string `json:"resource_kind"`
	ResourceIdentityInput string `json:"resource_identity_input"`

	EvidenceNodeIDs   []string `json:"evidence_node_ids"`
	EvidenceNodeKinds []string `json:"evidence_node_kinds"`
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
	if w.TopologyNormalizationVersion != WitnessTopologyNormalizationVersion {
		return fmt.Errorf(
			"witness topology normalization version %d is not supported (want %d)",
			w.TopologyNormalizationVersion, WitnessTopologyNormalizationVersion,
		)
	}
	if w.PredictedEdgeKind != PredictedEdgeKindCanReach {
		return fmt.Errorf(
			"witness predicted_edge_kind %q is not runnable (want %q)",
			w.PredictedEdgeKind, PredictedEdgeKindCanReach,
		)
	}
	if strings.TrimSpace(w.AgentID) == "" {
		return errors.New("witness agent_id must not be empty")
	}
	if w.AgentKind != "AgentInstance" {
		return errors.New("witness agent_kind must be AgentInstance")
	}
	if strings.TrimSpace(w.CredentialID) == "" {
		return errors.New("witness credential_id must not be empty")
	}
	if w.CredentialKind != "Credential" {
		return errors.New("witness credential_kind must be Credential")
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
	if w.ServerKind != "MCPServer" {
		return errors.New("witness server_kind must be MCPServer")
	}
	if strings.TrimSpace(w.ServerIdentityID) == "" {
		return errors.New("witness server_identity_id must not be empty")
	}
	switch w.ServiceScope {
	case ingest.ScopeCollectionPoint, ingest.ScopeNetworkContext, ingest.ScopeArtifactLocal:
	default:
		return errors.New("witness service_scope is invalid")
	}
	if strings.TrimSpace(w.ServiceScopeID) == "" {
		return errors.New("witness service_scope_id must not be empty")
	}
	if bound := ingest.ScopedNodeID(w.ServiceScope, w.ServiceScopeID, w.ServerIdentityID); bound != w.ServerID {
		return errors.New("witness server_id does not bind to its service scope and endpoint identity")
	}
	if strings.TrimSpace(w.ResourceID) == "" {
		return errors.New("witness resource_id must not be empty")
	}
	if w.ResourceKind != "MCPResource" {
		return errors.New("witness resource_kind must be MCPResource")
	}
	if strings.TrimSpace(w.ResourceIdentityInput) == "" {
		return errors.New("witness resource_identity_input must not be empty")
	}
	rawResourceID := ingest.ComputeNodeID("MCPResource", w.ServerIdentityID, w.ResourceIdentityInput)
	if bound := ingest.ScopedNodeID(w.ServiceScope, w.ServiceScopeID, rawResourceID); bound != w.ResourceID {
		return fmt.Errorf(
			"witness resource_id does not bind to (server_id, resource_identity_input): forged or mismatched witness",
		)
	}
	if len(w.EvidenceNodeIDs) == 0 {
		return errors.New("witness evidence_node_ids must not be empty")
	}
	if len(w.EvidenceNodeKinds) != len(w.EvidenceNodeIDs) {
		return errors.New("witness evidence_node_ids and evidence_node_kinds must have equal length")
	}
	required := map[string]string{
		w.AgentID:      w.AgentKind,
		w.ServerID:     w.ServerKind,
		w.CredentialID: w.CredentialKind,
		w.ResourceID:   w.ResourceKind,
	}
	seenRequired := make(map[string]bool, len(required))
	for i, nodeID := range w.EvidenceNodeIDs {
		kind := w.EvidenceNodeKinds[i]
		if strings.TrimSpace(nodeID) == "" || strings.TrimSpace(kind) == "" {
			return fmt.Errorf("witness evidence topology[%d] requires node id and kind", i)
		}
		if ingest.ConcreteNodeKind([]string{kind}) != kind {
			return fmt.Errorf("witness evidence_node_kinds[%d] is not a normalized concrete kind", i)
		}
		if requiredKind, ok := required[nodeID]; ok {
			if kind != requiredKind {
				return fmt.Errorf("witness evidence topology kind mismatch for required node")
			}
			seenRequired[nodeID] = true
		}
	}
	if w.EvidenceNodeIDs[0] != w.AgentID || w.EvidenceNodeKinds[0] != w.AgentKind {
		return errors.New("witness evidence topology must begin with the source agent")
	}
	if w.EvidenceNodeIDs[len(w.EvidenceNodeIDs)-1] != w.ResourceID ||
		w.EvidenceNodeKinds[len(w.EvidenceNodeKinds)-1] != w.ResourceKind {
		return errors.New("witness evidence topology must end with the target resource")
	}
	for nodeID := range required {
		if !seenRequired[nodeID] {
			return errors.New("witness evidence topology is missing a required identity node")
		}
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

package campaign

import (
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	testServerID   = "sha256:server"
	testAgentID    = "sha256:agent"
	testCredID     = "sha256:credential"
	testResURI     = "postgres://prod/customers"
	testCredMateri = "sk-super-secret-value"
	testScopeID    = "sha256:test-service-scope"
)

func testScopedServerID() string {
	return ingest.ScopedNodeID(ingest.ScopeNetworkContext, testScopeID, testServerID)
}

func testResourceID() string {
	rawID := ingest.ComputeNodeID("MCPResource", testServerID, testResURI)
	return ingest.ScopedNodeID(ingest.ScopeNetworkContext, testScopeID, rawID)
}

func validWitness() Witness {
	resID := testResourceID()
	return Witness{
		SchemaVersion:                WitnessSchemaVersion,
		TopologyNormalizationVersion: WitnessTopologyNormalizationVersion,
		PublicationRevision:          7,
		PredictedEdgeKind:            PredictedEdgeKindCanReach,
		AgentID:                      testAgentID,
		AgentKind:                    "AgentInstance",
		CredentialID:                 testCredID,
		CredentialKind:               "Credential",
		CredentialValueHash:          common.HashCredentialValue(testCredMateri),
		CredentialMergeKey:           CredentialMergeKeyValueHash,
		ServerID:                     testScopedServerID(),
		ServerKind:                   "MCPServer",
		ServerIdentityID:             testServerID,
		ServiceScope:                 ingest.ScopeNetworkContext,
		ServiceScopeID:               testScopeID,
		ResourceID:                   resID,
		ResourceKind:                 "MCPResource",
		ResourceIdentityInput:        testResURI,
		EvidenceNodeIDs: []string{
			testAgentID, "sha256:tool-1", testScopedServerID(), testCredID, resID,
		},
		EvidenceNodeKinds: []string{
			"AgentInstance", "MCPTool", "MCPServer", "Credential", "MCPResource",
		},
	}
}

func TestWitnessValidateValid(t *testing.T) {
	if err := validWitness().Validate(); err != nil {
		t.Fatalf("valid witness rejected: %v", err)
	}
}

func TestWitnessValidateStaleSchema(t *testing.T) {
	w := validWitness()
	w.SchemaVersion = WitnessSchemaVersion + 1
	if err := w.Validate(); err == nil {
		t.Fatal("stale/forward schema version must be rejected")
	}
}

func TestWitnessValidateForgedResourceBinding(t *testing.T) {
	w := validWitness()
	// Tamper the URI so it no longer hashes to resource_id.
	w.ResourceIdentityInput = "postgres://prod/other"
	if err := w.Validate(); err == nil {
		t.Fatal("resource_id that does not bind to (server_id, resource_uri) must be rejected")
	}
}

func TestWitnessValidateHashOnlyMergeKey(t *testing.T) {
	w := validWitness()
	w.CredentialMergeKey = "identity"
	if err := w.Validate(); err == nil {
		t.Fatal("synthetic-identity credential must be rejected as not runnable")
	}
}

func TestWitnessValidateMissingFields(t *testing.T) {
	base := validWitness()
	mutators := map[string]func(*Witness){
		"empty agent_id":            func(w *Witness) { w.AgentID = "" },
		"wrong agent_kind":          func(w *Witness) { w.AgentKind = "A2AAgent" },
		"empty credential_id":       func(w *Witness) { w.CredentialID = "" },
		"wrong credential_kind":     func(w *Witness) { w.CredentialKind = "Identity" },
		"empty value_hash":          func(w *Witness) { w.CredentialValueHash = "" },
		"empty server_id":           func(w *Witness) { w.ServerID = "" },
		"wrong server_kind":         func(w *Witness) { w.ServerKind = "Host" },
		"empty server identity":     func(w *Witness) { w.ServerIdentityID = "" },
		"empty service scope":       func(w *Witness) { w.ServiceScope = "" },
		"empty service scope id":    func(w *Witness) { w.ServiceScopeID = "" },
		"empty resource identity":   func(w *Witness) { w.ResourceIdentityInput = "" },
		"wrong resource_kind":       func(w *Witness) { w.ResourceKind = "Credential" },
		"zero publication_revision": func(w *Witness) { w.PublicationRevision = 0 },
		"wrong topology version":    func(w *Witness) { w.TopologyNormalizationVersion++ },
		"empty evidence topology":   func(w *Witness) { w.EvidenceNodeIDs = nil; w.EvidenceNodeKinds = nil },
		"topology length mismatch":  func(w *Witness) { w.EvidenceNodeKinds = w.EvidenceNodeKinds[:1] },
		"wrong predicted_edge_kind": func(w *Witness) { w.PredictedEdgeKind = "HAS_ACCESS_TO" },
		"topology missing credential": func(w *Witness) {
			w.EvidenceNodeIDs = []string{w.AgentID, w.ServerID, w.ResourceID}
			w.EvidenceNodeKinds = []string{w.AgentKind, w.ServerKind, w.ResourceKind}
		},
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			w := base
			w.EvidenceNodeIDs = append([]string(nil), base.EvidenceNodeIDs...)
			w.EvidenceNodeKinds = append([]string(nil), base.EvidenceNodeKinds...)
			mutate(&w)
			if err := w.Validate(); err == nil {
				t.Fatalf("expected rejection for %q", name)
			}
		})
	}
}

func TestWitnessFingerprintStableAndTamperEvident(t *testing.T) {
	w := validWitness()
	fp1 := w.Fingerprint()
	if fp1 == "" {
		t.Fatal("fingerprint must not be empty")
	}
	if w.Fingerprint() != fp1 {
		t.Fatal("fingerprint must be stable across calls")
	}
	tampered := w
	tampered.CredentialValueHash = "sha256:different"
	if tampered.Fingerprint() == fp1 {
		t.Fatal("fingerprint must change when a witness field is tampered")
	}
}

func TestMatchCredentialMaterial(t *testing.T) {
	w := validWitness()

	if err := MatchCredentialMaterial(w, testCredMateri); err != nil {
		t.Fatalf("matching material rejected: %v", err)
	}

	// Reject hash-only / no material as a PRECONDITION failure (not indeterminate).
	if err := MatchCredentialMaterial(w, ""); !errors.Is(err, ErrNotRunnable) {
		t.Fatalf("empty material must be ErrNotRunnable, got %v", err)
	}
	if err := MatchCredentialMaterial(w, "wrong-value"); !errors.Is(err, ErrNotRunnable) {
		t.Fatalf("mismatched material must be ErrNotRunnable, got %v", err)
	}

	synthetic := w
	synthetic.CredentialMergeKey = "identity"
	if err := MatchCredentialMaterial(synthetic, testCredMateri); !errors.Is(err, ErrNotRunnable) {
		t.Fatalf("synthetic-identity credential must be ErrNotRunnable, got %v", err)
	}
}

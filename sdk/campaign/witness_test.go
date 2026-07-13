package campaign

import (
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	testServerID   = "sha256:server"
	testCredID     = "sha256:credential"
	testResURI     = "postgres://prod/customers"
	testCredMateri = "sk-super-secret-value"
)

func testResourceID() string {
	return ingest.ComputeNodeID("MCPResource", testServerID, testResURI)
}

func validWitness() Witness {
	resID := testResourceID()
	return Witness{
		SchemaVersion:       WitnessSchemaVersion,
		PublicationRevision: 7,
		PredictedEdgeKind:   PredictedEdgeKindCanReach,
		CredentialID:        testCredID,
		CredentialValueHash: common.HashCredentialValue(testCredMateri),
		CredentialMergeKey:  CredentialMergeKeyValueHash,
		ServerID:            testServerID,
		ResourceID:          resID,
		ResourceURI:         testResURI,
		PathTopology: []PathHop{
			{NodeID: "sha256:agent", Kind: "AgentInstance"},
			{NodeID: testServerID, Kind: "MCPServer"},
			{NodeID: testCredID, Kind: "Credential"},
			{NodeID: resID, Kind: "MCPResource"},
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
	w.ResourceURI = "postgres://prod/other"
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
		"empty credential_id":         func(w *Witness) { w.CredentialID = "" },
		"empty value_hash":            func(w *Witness) { w.CredentialValueHash = "" },
		"empty server_id":             func(w *Witness) { w.ServerID = "" },
		"empty resource_uri":          func(w *Witness) { w.ResourceURI = "" },
		"zero publication_revision":   func(w *Witness) { w.PublicationRevision = 0 },
		"empty path_topology":         func(w *Witness) { w.PathTopology = nil },
		"wrong predicted_edge_kind":   func(w *Witness) { w.PredictedEdgeKind = "HAS_ACCESS_TO" },
		"topology missing credential": func(w *Witness) { w.PathTopology = []PathHop{{NodeID: w.ResourceID, Kind: "MCPResource"}} },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			w := base
			// Deep-copy the slice header so mutators don't alias base.
			w.PathTopology = append([]PathHop(nil), base.PathTopology...)
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

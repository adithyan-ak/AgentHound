package cli

import (
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestValidateStorageBindingStateMatrix(t *testing.T) {
	origin := ingest.CollectionOrigin{HostID: "host-a", NetworkRealmID: "realm-a"}
	expected, err := binding.NewMarker(origin, "7bc1f56e-c890-4de5-9cc5-921797176fa6")
	if err != nil {
		t.Fatal(err)
	}
	otherPair, err := binding.NewMarker(origin, "ee2f3afe-209e-42fb-8685-af55caa7e58d")
	if err != nil {
		t.Fatal(err)
	}
	otherRealm, err := binding.NewMarker(
		ingest.CollectionOrigin{HostID: "host-b", NetworkRealmID: "realm-a"},
		expected.StoragePairID,
	)
	if err != nil {
		t.Fatal(err)
	}

	marker := func(value binding.Marker) *binding.Marker {
		copy := value
		return &copy
	}
	tests := []struct {
		name       string
		postgres   appdb.StorageInspection
		neo4j      graph.StorageBindingInspection
		wantErr    bool
		wantPhrase string
	}{
		{
			name:     "fresh empty pair",
			postgres: appdb.StorageInspection{ProductEmpty: true},
			neo4j:    graph.StorageBindingInspection{ProductEmpty: true},
		},
		{
			name:     "exact bound nonempty pair",
			postgres: appdb.StorageInspection{Marker: marker(expected)},
			neo4j:    graph.StorageBindingInspection{Marker: marker(expected)},
		},
		{
			name:     "crash recovery PostgreSQL stamped first",
			postgres: appdb.StorageInspection{Marker: marker(expected), ProductEmpty: true},
			neo4j:    graph.StorageBindingInspection{ProductEmpty: true},
		},
		{
			name:     "crash recovery Neo4j stamped first",
			postgres: appdb.StorageInspection{ProductEmpty: true},
			neo4j:    graph.StorageBindingInspection{Marker: marker(expected), ProductEmpty: true},
		},
		{
			name:       "legacy PostgreSQL data",
			postgres:   appdb.StorageInspection{ProductEmpty: false},
			neo4j:      graph.StorageBindingInspection{ProductEmpty: true},
			wantErr:    true,
			wantPhrase: "nonempty legacy or crossed storage",
		},
		{
			name:       "legacy Neo4j data",
			postgres:   appdb.StorageInspection{ProductEmpty: true},
			neo4j:      graph.StorageBindingInspection{ProductEmpty: false},
			wantErr:    true,
			wantPhrase: "nonempty legacy or crossed storage",
		},
		{
			name:       "different configured realm",
			postgres:   appdb.StorageInspection{Marker: marker(otherRealm)},
			neo4j:      graph.StorageBindingInspection{Marker: marker(otherRealm)},
			wantErr:    true,
			wantPhrase: "does not match configured",
		},
		{
			name:       "crossed storage pair",
			postgres:   appdb.StorageInspection{Marker: marker(expected)},
			neo4j:      graph.StorageBindingInspection{Marker: marker(otherPair)},
			wantErr:    true,
			wantPhrase: "does not match configured",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStorageBindingState(expected, test.postgres, test.neo4j)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), test.wantPhrase) {
					t.Fatalf("error = %v, want phrase %q", err, test.wantPhrase)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

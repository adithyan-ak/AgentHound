package cli

import (
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestResolveStorageBindingMatrix(t *testing.T) {
	expected, err := binding.NewMarker("7bc1f56e-c890-4de5-9cc5-921797176fa6")
	if err != nil {
		t.Fatal(err)
	}
	otherPair, err := binding.NewMarker("ee2f3afe-209e-42fb-8685-af55caa7e58d")
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
		wantMarker *binding.Marker
		wantErr    bool
		wantPhrase string
	}{
		{
			name:     "fresh empty pair",
			postgres: appdb.StorageInspection{ProductEmpty: true},
			neo4j:    graph.StorageBindingInspection{ProductEmpty: true},
		},
		{
			name:       "exact bound nonempty pair",
			postgres:   appdb.StorageInspection{Marker: marker(expected)},
			neo4j:      graph.StorageBindingInspection{Marker: marker(expected)},
			wantMarker: marker(expected),
		},
		{
			name:       "crash recovery PostgreSQL stamped first",
			postgres:   appdb.StorageInspection{Marker: marker(expected), ProductEmpty: true},
			neo4j:      graph.StorageBindingInspection{ProductEmpty: true},
			wantMarker: marker(expected),
		},
		{
			name:       "crash recovery Neo4j stamped first",
			postgres:   appdb.StorageInspection{ProductEmpty: true},
			neo4j:      graph.StorageBindingInspection{Marker: marker(expected), ProductEmpty: true},
			wantMarker: marker(expected),
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
			name:       "crossed storage pair",
			postgres:   appdb.StorageInspection{Marker: marker(expected)},
			neo4j:      graph.StorageBindingInspection{Marker: marker(otherPair)},
			wantErr:    true,
			wantPhrase: "different volume pairs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := resolveStorageBinding(test.postgres, test.neo4j)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), test.wantPhrase) {
					t.Fatalf("error = %v, want phrase %q", err, test.wantPhrase)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.wantMarker != nil && !resolved.Equal(*test.wantMarker) {
				t.Fatalf("marker = %+v, want %+v", resolved, *test.wantMarker)
			}
			if test.wantMarker == nil {
				if err := resolved.Validate(); err != nil {
					t.Fatalf("generated marker is invalid: %v", err)
				}
			}
		})
	}
}

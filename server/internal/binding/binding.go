// Package binding defines the server-internal PostgreSQL/Neo4j storage-pair
// boundary. Collection provenance is deliberately independent from it.
package binding

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const CurrentVersion = 2

var ErrMarkerMissing = errors.New("storage binding marker is missing")

type Marker struct {
	BindingVersion int
	StoragePairID  string
}

func NewMarker(storagePairID string) (Marker, error) {
	parsed, err := uuid.Parse(storagePairID)
	if err != nil || parsed.String() != storagePairID {
		return Marker{}, fmt.Errorf("storage_pair_id must be a canonical lowercase UUID")
	}
	return Marker{
		BindingVersion: CurrentVersion,
		StoragePairID:  storagePairID,
	}, nil
}

func (m Marker) Validate() error {
	_, err := NewMarker(m.StoragePairID)
	if err != nil {
		return err
	}
	if m.BindingVersion != CurrentVersion {
		return fmt.Errorf(
			"binding_version is %d, supported version is %d",
			m.BindingVersion,
			CurrentVersion,
		)
	}
	return nil
}

func (m Marker) Equal(other Marker) bool {
	return m.BindingVersion == other.BindingVersion &&
		m.StoragePairID == other.StoragePairID
}

type MarkerReader interface {
	ReadStorageBinding(context.Context) (Marker, error)
}

type StorageError struct {
	Message string
	Cause   error
}

func (e *StorageError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("storage binding %s: %v", e.Message, e.Cause)
	}
	return "storage binding " + e.Message
}

func (e *StorageError) Unwrap() error { return e.Cause }

func IsStorageError(err error) bool {
	var target *StorageError
	return errors.As(err, &target)
}

type Guard struct {
	expected Marker
	postgres MarkerReader
	neo4j    MarkerReader
}

func NewGuard(expected Marker, postgres, neo4j MarkerReader) (*Guard, error) {
	if err := expected.Validate(); err != nil {
		return nil, fmt.Errorf("expected storage binding: %w", err)
	}
	if postgres == nil || neo4j == nil {
		return nil, fmt.Errorf("both PostgreSQL and Neo4j binding readers are required")
	}
	return &Guard{expected: expected, postgres: postgres, neo4j: neo4j}, nil
}

// Verify is deliberately read-only. It runs before validation paths that may
// write campaign-rejection audits, scan lifecycle rows, or graph state.
func (g *Guard) Verify(ctx context.Context) error {
	postgresMarker, err := g.postgres.ReadStorageBinding(ctx)
	if err != nil {
		return &StorageError{Message: "PostgreSQL marker read failed", Cause: err}
	}
	neo4jMarker, err := g.neo4j.ReadStorageBinding(ctx)
	if err != nil {
		return &StorageError{Message: "Neo4j marker read failed", Cause: err}
	}
	if !postgresMarker.Equal(g.expected) || !neo4jMarker.Equal(g.expected) ||
		!postgresMarker.Equal(neo4jMarker) {
		return &StorageError{Message: "markers do not match the configured immutable storage pair"}
	}
	return nil
}

// Package binding defines the immutable host/network/storage boundary shared
// by the server bootstrap and ingest admission paths.
package binding

import (
	"context"
	"errors"
	"fmt"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/google/uuid"
)

const CurrentVersion = 1

var ErrMarkerMissing = errors.New("storage binding marker is missing")

type Marker struct {
	BindingVersion int
	StoragePairID  string
	HostID         string
	NetworkRealmID string
	RealmSHA256    string
}

func NewMarker(origin ingest.CollectionOrigin, storagePairID string) (Marker, error) {
	if err := origin.Validate(); err != nil {
		return Marker{}, fmt.Errorf("origin: %w", err)
	}
	parsed, err := uuid.Parse(storagePairID)
	if err != nil || parsed.String() != storagePairID {
		return Marker{}, fmt.Errorf("storage_pair_id must be a canonical lowercase UUID")
	}
	return Marker{
		BindingVersion: CurrentVersion,
		StoragePairID:  storagePairID,
		HostID:         origin.HostID,
		NetworkRealmID: origin.NetworkRealmID,
		RealmSHA256:    ingest.OriginDigest(origin),
	}, nil
}

func (m Marker) Origin() ingest.CollectionOrigin {
	return ingest.CollectionOrigin{HostID: m.HostID, NetworkRealmID: m.NetworkRealmID}
}

func (m Marker) Validate() error {
	expected, err := NewMarker(m.Origin(), m.StoragePairID)
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
	if m.RealmSHA256 != expected.RealmSHA256 {
		return fmt.Errorf("realm_sha256 does not match host_id and network_realm_id")
	}
	return nil
}

func (m Marker) Equal(other Marker) bool {
	return m.BindingVersion == other.BindingVersion &&
		m.StoragePairID == other.StoragePairID &&
		m.HostID == other.HostID &&
		m.NetworkRealmID == other.NetworkRealmID &&
		m.RealmSHA256 == other.RealmSHA256
}

type MarkerReader interface {
	ReadStorageBinding(context.Context) (Marker, error)
}

type RealmMismatchError struct {
	Expected ingest.CollectionOrigin
	Actual   ingest.CollectionOrigin
	Cause    error
}

func (e *RealmMismatchError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("collection realm mismatch: %v", e.Cause)
	}
	return fmt.Sprintf(
		"collection realm mismatch: artifact host_id=%q network_realm_id=%q; database admits host_id=%q network_realm_id=%q",
		e.Actual.HostID,
		e.Actual.NetworkRealmID,
		e.Expected.HostID,
		e.Expected.NetworkRealmID,
	)
}

func IsRealmMismatch(err error) bool {
	var target *RealmMismatchError
	return errors.As(err, &target)
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

// Admit is deliberately read-only. It runs before validation paths that may
// write campaign-rejection audits, scan lifecycle rows, or graph state.
func (g *Guard) Admit(ctx context.Context, origin ingest.CollectionOrigin) error {
	if err := origin.Validate(); err != nil {
		return &RealmMismatchError{Expected: g.expected.Origin(), Actual: origin, Cause: err}
	}
	if origin != g.expected.Origin() {
		return &RealmMismatchError{Expected: g.expected.Origin(), Actual: origin}
	}

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

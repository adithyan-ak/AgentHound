package binding

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const pairID = "7bc1f56e-c890-4de5-9cc5-921797176fa6"

type markerReader struct {
	marker Marker
	err    error
}

func (r markerReader) ReadStorageBinding(context.Context) (Marker, error) {
	return r.marker, r.err
}

func TestGuardVerifiesStoragePairOnly(t *testing.T) {
	marker, err := NewMarker(pairID)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(marker, markerReader{marker: marker}, markerReader{marker: marker})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Verify(context.Background()); err != nil {
		t.Fatalf("matching storage pair rejected: %v", err)
	}
}

func TestGuardRejectsStorageDisagreement(t *testing.T) {
	marker, _ := NewMarker(pairID)
	other, _ := NewMarker("ee2f3afe-209e-42fb-8685-af55caa7e58d")
	guard, err := NewGuard(marker, markerReader{marker: marker}, markerReader{marker: other})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Verify(context.Background()); !IsStorageError(err) {
		t.Fatalf("storage mismatch error = %v", err)
	}

	guard, err = NewGuard(
		marker,
		markerReader{err: errors.New("postgres unavailable")},
		markerReader{marker: marker},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Verify(context.Background()); !IsStorageError(err) {
		t.Fatalf("storage read error = %v", err)
	}
}

func TestUnsupportedBindingVersionFailsWithResetGuidance(t *testing.T) {
	unsupported := Marker{
		BindingVersion: CurrentVersion + 1,
		StoragePairID:  pairID,
	}
	err := unsupported.Validate()
	for _, phrase := range []string{
		"binding_version is 2, supported version is 1",
		"recreate both PostgreSQL and Neo4j volumes together",
		"recollect with ingest v1",
	} {
		if err == nil || !strings.Contains(err.Error(), phrase) {
			t.Fatalf("unsupported marker error = %v, want phrase %q", err, phrase)
		}
	}

	current, err := NewMarker(pairID)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(
		current,
		markerReader{marker: unsupported},
		markerReader{marker: current},
	)
	if err != nil {
		t.Fatal(err)
	}
	err = guard.Verify(context.Background())
	if !IsStorageError(err) || !strings.Contains(err.Error(), resetGuidance) {
		t.Fatalf("unsupported guard error = %v", err)
	}
}

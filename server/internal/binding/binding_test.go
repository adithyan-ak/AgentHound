package binding

import (
	"context"
	"errors"
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

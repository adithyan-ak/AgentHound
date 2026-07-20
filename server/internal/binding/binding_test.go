package binding

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const pairID = "7bc1f56e-c890-4de5-9cc5-921797176fa6"

type markerReader struct {
	marker Marker
	err    error
}

func (r markerReader) ReadStorageBinding(context.Context) (Marker, error) {
	return r.marker, r.err
}

func TestGuardAdmission(t *testing.T) {
	origin := ingest.CollectionOrigin{HostID: "host-a", NetworkRealmID: "realm-a"}
	marker, err := NewMarker(origin, pairID)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(marker, markerReader{marker: marker}, markerReader{marker: marker})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Admit(context.Background(), origin); err != nil {
		t.Fatalf("exact origin rejected: %v", err)
	}
	if err := guard.Admit(context.Background(), ingest.CollectionOrigin{
		HostID: "host-b", NetworkRealmID: "realm-a",
	}); !IsRealmMismatch(err) {
		t.Fatalf("wrong host error = %v", err)
	}
	if err := guard.Admit(context.Background(), ingest.CollectionOrigin{}); !IsRealmMismatch(err) {
		t.Fatalf("missing origin error = %v", err)
	}
}

func TestGuardRejectsStorageDisagreement(t *testing.T) {
	origin := ingest.CollectionOrigin{HostID: "host-a", NetworkRealmID: "realm-a"}
	marker, _ := NewMarker(origin, pairID)
	other, _ := NewMarker(origin, "ee2f3afe-209e-42fb-8685-af55caa7e58d")
	guard, err := NewGuard(marker, markerReader{marker: marker}, markerReader{marker: other})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Admit(context.Background(), origin); !IsStorageError(err) {
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
	if err := guard.Admit(context.Background(), origin); !IsStorageError(err) {
		t.Fatalf("storage read error = %v", err)
	}
}

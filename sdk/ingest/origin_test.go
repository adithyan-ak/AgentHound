package ingest

import "testing"

func testEvidence(kind, hex string) IdentityEvidence {
	return IdentityEvidence{Kind: kind, Digest: "hmac-sha256:" + hex}
}

func TestCollectionIdentityValidationAndDerivation(t *testing.T) {
	osEvidence := testEvidence("os_instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	principal := testEvidence("principal", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	route := testEvidence("route_private", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	record := NewCollectionIdentity(
		[]IdentityEvidence{principal, osEvidence},
		[]IdentityEvidence{route},
		NetworkClassPrivate,
	)
	if err := record.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if record.Quality != IdentityQualityStrong {
		t.Fatalf("quality = %q, want strong", record.Quality)
	}
	if !IsCanonicalSHA256(record.CollectionPointID) || !IsCanonicalSHA256(record.NetworkContextID) {
		t.Fatalf("noncanonical derived IDs: %+v", record)
	}

	tampered := record
	tampered.NetworkContextID = record.CollectionPointID
	if err := tampered.Validate(); err == nil {
		t.Fatal("tampered network context unexpectedly validated")
	}
}

func TestCollectionIdentityWeakAndOffline(t *testing.T) {
	record := NewCollectionIdentity(
		[]IdentityEvidence{testEvidence("hostname", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")},
		[]IdentityEvidence{testEvidence("offline", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")},
		NetworkClassOffline,
	)
	if err := record.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if record.Quality != IdentityQualityWeak {
		t.Fatalf("quality = %q, want weak", record.Quality)
	}
}

func TestCollectionIdentityRejectsUnsupportedAndMisclassifiedEvidence(t *testing.T) {
	record := NewCollectionIdentity(
		[]IdentityEvidence{
			testEvidence("os_instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			testEvidence("principal", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		},
		[]IdentityEvidence{testEvidence("route_private", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")},
		NetworkClassPublic,
	)
	if err := record.Validate(); err == nil {
		t.Fatal("misclassified network evidence unexpectedly validated")
	}

	record = NewCollectionIdentity(
		[]IdentityEvidence{testEvidence("invented", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		[]IdentityEvidence{testEvidence("offline", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
		NetworkClassOffline,
	)
	if err := record.Validate(); err == nil {
		t.Fatal("unsupported evidence kind unexpectedly validated")
	}
}

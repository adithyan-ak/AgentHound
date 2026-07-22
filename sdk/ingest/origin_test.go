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

func TestCollectionIdentityKeepsPointAndNetworkQualityIndependent(t *testing.T) {
	record := NewCollectionIdentity(
		[]IdentityEvidence{
			testEvidence("os_instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			testEvidence("principal", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		},
		[]IdentityEvidence{
			testEvidence("network_visibility_unknown", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
			testEvidence("route_private", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
		},
		NetworkClassPrivate,
	)
	if err := record.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if record.Quality != IdentityQualityStrong || record.NetworkQuality != IdentityQualityUnknown {
		t.Fatalf("independent qualities = point %q network %q", record.Quality, record.NetworkQuality)
	}

	tampered := record
	tampered.NetworkQuality = IdentityQualityStrong
	if err := tampered.Validate(); err == nil {
		t.Fatal("tampered network quality unexpectedly validated")
	}
}

func TestCollectionIdentityDowngradesUnknownExecutionScopeOnly(t *testing.T) {
	record := NewCollectionIdentity(
		[]IdentityEvidence{
			testEvidence("execution_scope_unknown", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			testEvidence("os_instance", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			testEvidence("principal", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
		},
		[]IdentityEvidence{testEvidence("route_private", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")},
		NetworkClassPrivate,
	)
	if err := record.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if record.Quality != IdentityQualityWeak || record.NetworkQuality != IdentityQualityStrong {
		t.Fatalf("qualities = point %q network %q", record.Quality, record.NetworkQuality)
	}
}

func TestCollectionIdentityValidatesDisplayLabels(t *testing.T) {
	record := NewCollectionIdentity(
		[]IdentityEvidence{testEvidence("hostname", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		[]IdentityEvidence{testEvidence("offline", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
		NetworkClassOffline,
	)
	record.Display = CollectionDisplayLabels{Hostname: "target-01", OS: "linux", Architecture: "amd64"}
	if err := record.Validate(); err != nil {
		t.Fatalf("valid display labels rejected: %v", err)
	}
	unlabelled := NewCollectionIdentity(record.Evidence, record.NetworkEvidence, record.NetworkClass)
	if record.CollectionPointID != unlabelled.CollectionPointID ||
		record.NetworkContextID != unlabelled.NetworkContextID {
		t.Fatal("display labels changed authoritative identity")
	}
	record.Display.Hostname = "target\nspoof"
	if err := record.Validate(); err == nil {
		t.Fatal("control character in display hostname unexpectedly validated")
	}
	record.Display.Hostname = "target\u202espoof"
	if err := record.Validate(); err == nil {
		t.Fatal("format character in display hostname unexpectedly validated")
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

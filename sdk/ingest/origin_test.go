package ingest

import (
	"strings"
	"testing"
)

func TestCollectionOriginValidate(t *testing.T) {
	t.Parallel()
	valid := []CollectionOrigin{
		{HostID: "defcon-laptop", NetworkRealmID: "defcon.lab_1"},
		{HostID: "h", NetworkRealmID: "0"},
	}
	for _, origin := range valid {
		if err := origin.Validate(); err != nil {
			t.Errorf("Validate(%+v): %v", origin, err)
		}
	}

	invalid := []CollectionOrigin{
		{},
		{HostID: "Host-A", NetworkRealmID: "lab"},
		{HostID: "host-a", NetworkRealmID: " lab"},
		{HostID: "-host", NetworkRealmID: "lab"},
		{HostID: strings.Repeat("a", MaxOriginIDLength+1), NetworkRealmID: "lab"},
	}
	for _, origin := range invalid {
		if err := origin.Validate(); err == nil {
			t.Errorf("Validate(%+v) unexpectedly succeeded", origin)
		}
	}
}

func TestOriginDigestSeparatesHostAndRealm(t *testing.T) {
	t.Parallel()
	base := OriginDigest(CollectionOrigin{HostID: "host-a", NetworkRealmID: "realm-a"})
	if len(base) != 64 {
		t.Fatalf("digest length = %d, want 64", len(base))
	}
	for _, other := range []CollectionOrigin{
		{HostID: "host-b", NetworkRealmID: "realm-a"},
		{HostID: "host-a", NetworkRealmID: "realm-b"},
	} {
		if got := OriginDigest(other); got == base {
			t.Fatalf("origin %+v collided with base", other)
		}
	}
}

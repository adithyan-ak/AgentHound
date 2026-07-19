package cli

import (
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

var testCollectionOrigin = ingest.CollectionOrigin{
	HostID:         "test-host",
	NetworkRealmID: "test-realm",
}

// TestMain gives direct runX unit tests the same origin configuration that
// Cobra's PersistentPreRunE supplies in production. Individual missing-origin
// tests replace cfg explicitly, so this does not weaken the fail-closed case.
func TestMain(m *testing.M) {
	_ = os.Setenv("AGENTHOUND_HOST_ID", testCollectionOrigin.HostID)
	_ = os.Setenv("AGENTHOUND_NETWORK_REALM_ID", testCollectionOrigin.NetworkRealmID)
	cfg = clientcfg.Load()
	os.Exit(m.Run())
}

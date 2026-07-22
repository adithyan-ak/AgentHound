package servercfg

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestServerConfigHasNoManualIdentityOrPairingInputs(t *testing.T) {
	t.Setenv("AGENTHOUND_HOST_ID", "ignored-host")
	t.Setenv("AGENTHOUND_NETWORK_REALM_ID", "ignored-network")
	t.Setenv("AGENTHOUND_STORAGE_PAIR_ID", "ignored-pair")
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("log-level", "", "")
	flags.String("bind", "", "")
	flags.String("neo4j-uri", "", "")
	flags.String("neo4j-user", "", "")
	flags.String("neo4j-password", "", "")
	flags.String("pg-uri", "", "")
	flags.String("cors-origins", "", "")
	cfg := LoadWithFlags(flags)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

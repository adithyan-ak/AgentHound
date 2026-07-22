package clientcfg

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestConfigHasNoManualIdentityInputs(t *testing.T) {
	t.Setenv("AGENTHOUND_HOST_ID", "ignored-host")
	t.Setenv("AGENTHOUND_NETWORK_REALM_ID", "ignored-network")
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("log-level", "", "")
	flags.String("output", "", "")
	flags.Int("concurrency", 0, "")
	cfg := LoadWithFlags(flags)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

package clientcfg

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestCollectionOriginResolution(t *testing.T) {
	t.Setenv("AGENTHOUND_HOST_ID", "env-host")
	t.Setenv("AGENTHOUND_NETWORK_REALM_ID", "env-realm")
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("host-id", "", "")
	flags.String("network-realm-id", "", "")

	cfg := LoadWithFlags(flags)
	origin, err := cfg.CollectionOrigin()
	if err != nil {
		t.Fatalf("CollectionOrigin: %v", err)
	}
	if origin.HostID != "env-host" || origin.NetworkRealmID != "env-realm" {
		t.Fatalf("origin = %+v", origin)
	}

	if err := flags.Set("host-id", "flag-host"); err != nil {
		t.Fatal(err)
	}
	if err := flags.Set("network-realm-id", "flag-realm"); err != nil {
		t.Fatal(err)
	}
	origin, err = LoadWithFlags(flags).CollectionOrigin()
	if err != nil {
		t.Fatalf("flag CollectionOrigin: %v", err)
	}
	if origin.HostID != "flag-host" || origin.NetworkRealmID != "flag-realm" {
		t.Fatalf("flag origin = %+v", origin)
	}
}

func TestCollectionOriginRequiredOnlyForCollection(t *testing.T) {
	cfg := &Config{LogLevel: "info", Concurrency: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("general config validation: %v", err)
	}
	if _, err := cfg.CollectionOrigin(); err == nil {
		t.Fatal("missing collection origin unexpectedly accepted")
	}

	cfg.HostID = "Host-A"
	cfg.NetworkRealmID = "realm-a"
	if err := cfg.Validate(); err == nil {
		t.Fatal("noncanonical origin unexpectedly accepted")
	}
}

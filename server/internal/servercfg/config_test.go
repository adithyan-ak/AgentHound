package servercfg

import (
	"testing"

	"github.com/spf13/pflag"
)

const testStoragePairID = "7bc1f56e-c890-4de5-9cc5-921797176fa6"

func TestStorageBindingResolution(t *testing.T) {
	t.Setenv("AGENTHOUND_HOST_ID", "env-host")
	t.Setenv("AGENTHOUND_NETWORK_REALM_ID", "env-realm")
	t.Setenv("AGENTHOUND_STORAGE_PAIR_ID", testStoragePairID)
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("host-id", "", "")
	flags.String("network-realm-id", "", "")
	flags.String("storage-pair-id", "", "")

	binding, err := LoadWithFlags(flags).Binding()
	if err != nil {
		t.Fatalf("environment Binding: %v", err)
	}
	if binding.Origin.HostID != "env-host" ||
		binding.Origin.NetworkRealmID != "env-realm" ||
		binding.StoragePairID != testStoragePairID {
		t.Fatalf("environment binding = %+v", binding)
	}

	if err := flags.Set("host-id", "flag-host"); err != nil {
		t.Fatal(err)
	}
	if err := flags.Set("network-realm-id", "flag-realm"); err != nil {
		t.Fatal(err)
	}
	const flagPairID = "8afaf137-2dc9-438c-97df-05b3ee24f77d"
	if err := flags.Set("storage-pair-id", flagPairID); err != nil {
		t.Fatal(err)
	}
	binding, err = LoadWithFlags(flags).Binding()
	if err != nil {
		t.Fatalf("flag Binding: %v", err)
	}
	if binding.Origin.HostID != "flag-host" ||
		binding.Origin.NetworkRealmID != "flag-realm" ||
		binding.StoragePairID != flagPairID {
		t.Fatalf("flag binding = %+v", binding)
	}
}

func TestStorageBindingValidation(t *testing.T) {
	cfg := &Config{
		LogLevel:       "info",
		Bind:           "127.0.0.1:8080",
		Neo4jURI:       "bolt://localhost:7687",
		PostgresURI:    "postgres://localhost/agenthound",
		HostID:         "host-a",
		NetworkRealmID: "realm-a",
		StoragePairID:  testStoragePairID,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	binding, err := cfg.Binding()
	if err != nil {
		t.Fatalf("Binding: %v", err)
	}
	if binding.Origin.HostID != "host-a" ||
		binding.Origin.NetworkRealmID != "realm-a" ||
		binding.StoragePairID != testStoragePairID {
		t.Fatalf("binding = %+v", binding)
	}
}

func TestStorageBindingRequiredOnlyForBootstrap(t *testing.T) {
	cfg := &Config{
		LogLevel:    "info",
		Bind:        "127.0.0.1:8080",
		Neo4jURI:    "bolt://localhost:7687",
		PostgresURI: "postgres://localhost/agenthound",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("general validation: %v", err)
	}
	if _, err := cfg.Binding(); err == nil {
		t.Fatal("missing storage binding unexpectedly accepted")
	}

	cfg.HostID = "host-a"
	cfg.NetworkRealmID = "realm-a"
	cfg.StoragePairID = "7BC1F56E-C890-4DE5-9CC5-921797176FA6"
	if err := cfg.Validate(); err == nil {
		t.Fatal("noncanonical UUID unexpectedly accepted")
	}
}

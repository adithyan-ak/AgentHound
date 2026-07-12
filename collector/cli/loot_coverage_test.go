package cli

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// TestBuildLootEnvelopeCoverage is the F5 counterexample for the NORMAL CLI
// loot envelope: the envelope the CLI emits carries REAL coverage derived from
// the loot result's probe counters — not a hand-authored or absent manifest.
// A /key/list 401 makes the envelope explicitly partial so the server ingest
// never treats the loot artifact's empty portions as an all-clear.
func TestBuildLootEnvelopeCoverage(t *testing.T) {
	res := &action.LootResult{
		Summary:       action.LootSummary{EndpointsProbed: 2, PartialFailures: 1, CredentialsFound: 3},
		PartialErrors: []string{"key/list: 401 unauthorized"},
	}
	env := buildLootEnvelope("172.20.0.10:4000", "litellm", "RTV-DEMO", res)

	if env.Meta.Coverage == nil {
		t.Fatal("loot envelope carries no coverage manifest (hand-authored/absent coverage regression)")
	}
	if env.Meta.Coverage.Status != ingest.StatusPartial {
		t.Errorf("coverage status = %q, want partial", env.Meta.Coverage.Status)
	}
	if len(env.Meta.Coverage.Methods) != 1 || env.Meta.Coverage.Methods[0].Method != "key/list" {
		t.Errorf("expected one failed method 'key/list' from PartialErrors, got %+v", env.Meta.Coverage.Methods)
	}
	if len(env.Meta.Coverage.ConstituentCollectors) != 1 || env.Meta.Coverage.ConstituentCollectors[0] != "loot:litellm" {
		t.Errorf("constituent collectors = %v, want [loot:litellm]", env.Meta.Coverage.ConstituentCollectors)
	}
	if env.Meta.SchemaVersion != ingest.CurrentSchemaVersion || env.Meta.IdentityVersion != ingest.CurrentIdentityVersion {
		t.Errorf("envelope schema/identity versions not pinned: schema=%d identity=%d", env.Meta.SchemaVersion, env.Meta.IdentityVersion)
	}
	if lt, _ := env.Meta.Extra["loot_type"].(string); lt != "litellm" {
		t.Errorf("loot_type watermark = %v, want litellm", env.Meta.Extra["loot_type"])
	}
}

// TestBuildLootEnvelopeCleanCoverage verifies a fully successful loot yields a
// complete envelope so absence within it is genuine evidence.
func TestBuildLootEnvelopeCleanCoverage(t *testing.T) {
	res := &action.LootResult{
		Summary: action.LootSummary{EndpointsProbed: 2, PartialFailures: 0, CredentialsFound: 1},
	}
	env := buildLootEnvelope("host:4000", "ollama", "", res)
	if env.Meta.Coverage == nil || env.Meta.Coverage.Status != ingest.StatusComplete {
		t.Fatalf("clean loot envelope coverage = %+v, want complete", env.Meta.Coverage)
	}
	if len(env.Meta.Coverage.Methods) != 0 {
		t.Errorf("clean loot recorded failed methods: %+v", env.Meta.Coverage.Methods)
	}
}

package modules_test

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/module"

	_ "github.com/adithyan-ak/agenthound/modules/a2a"
	_ "github.com/adithyan-ak/agenthound/modules/config"
	_ "github.com/adithyan-ak/agenthound/modules/credreach"
	_ "github.com/adithyan-ak/agenthound/modules/mcp"
)

func TestModulesRegistered(t *testing.T) {
	all := module.List()
	if len(all) != 3 {
		t.Fatalf("want 3 modules, got %d: %v", len(all), all)
	}

	enumeratorMetadata := module.ListByAction(action.Enumerate)
	if len(enumeratorMetadata) != 3 {
		t.Fatalf("want 3 enumerate metadata registrations, got %d", len(enumeratorMetadata))
	}
	for _, registered := range enumeratorMetadata {
		if _, ok := registered.(action.Enumerator); ok {
			t.Fatalf("%s unexpectedly implements action.Enumerator; update CLI dispatch and documentation together", registered.ID())
		}
	}

	for _, target := range []string{"mcp", "a2a", "config"} {
		m, ok := module.GetByTarget(target, action.Enumerate)
		if !ok {
			t.Fatalf("no module registered for target=%q action=enumerate", target)
		}
		if m.Target() != target {
			t.Fatalf("registry mis-routed %q to %q", target, m.Target())
		}
	}
}

// TestCampaignScenariosRegistered verifies the campaign scenario registry (a
// distinct mechanism from sdk/module) picked up the blank-imported cred-reach
// scenario via its init().
func TestCampaignScenariosRegistered(t *testing.T) {
	s, ok := campaign.Get("cred-reach")
	if !ok {
		t.Fatal("cred-reach scenario is not registered in the campaign registry")
	}
	if s.Version() < 1 {
		t.Fatalf("cred-reach scenario version = %d, want >= 1", s.Version())
	}
	if len(campaign.List()) < 1 {
		t.Fatal("campaign registry is empty")
	}
}

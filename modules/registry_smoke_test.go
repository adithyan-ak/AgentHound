package modules_test

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"

	_ "github.com/adithyan-ak/agenthound/modules/a2a"
	_ "github.com/adithyan-ak/agenthound/modules/config"
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

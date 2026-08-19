package cli

import (
	"testing"
)

func TestLeanCommandSurface(t *testing.T) {
	for _, verb := range []string{"scan", "revert", "version"} {
		t.Run(verb, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{verb})
			if err != nil {
				t.Fatalf("rootCmd.Find(%q): %v", verb, err)
			}
			if cmd == nil || cmd.RunE == nil {
				t.Fatalf("verb %q not registered or has no RunE", verb)
			}
		})
	}
	for _, removed := range []string{"campaign", "discover", "extract", "implant", "loot", "poison", "rules"} {
		if command, _, err := rootCmd.Find([]string{removed}); err == nil && command != rootCmd {
			t.Errorf("removed command %q is still registered", removed)
		}
	}
	if !rootCmd.CompletionOptions.DisableDefaultCmd {
		t.Error("default completion command expands the lean public command surface")
	}
}

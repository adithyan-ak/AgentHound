package cli

import (
	"testing"
)

// TestAllVerbsRegistered confirms every offensive + operational verb is wired
// into rootCmd with a real RunE. Guards against accidental de-registration.
func TestAllVerbsRegistered(t *testing.T) {
	for _, verb := range []string{"scan", "loot", "poison", "implant", "revert", "discover", "extract"} {
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
}

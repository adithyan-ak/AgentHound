package cli

import (
	"errors"
	"testing"
)

// TestStubsRegistered verifies each reserved verb is wired into rootCmd so
// `agenthound --help` lists it. This is the contract of "reserve the verb
// space without implementing anything" — break it and a future PR that adds
// `loot|extract|poison|implant` may collide with an existing alias.
func TestStubsRegistered(t *testing.T) {
	for _, verb := range []string{"loot", "extract", "poison", "implant"} {
		t.Run(verb, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{verb})
			if err != nil {
				t.Fatalf("rootCmd.Find(%q): %v", verb, err)
			}
			if cmd == nil || cmd.Use != verb {
				t.Fatalf("verb %q not registered (got %v)", verb, cmd)
			}
			if cmd.RunE == nil {
				t.Fatalf("verb %q has no RunE (cobra would print help instead of returning the stub error)", verb)
			}
		})
	}
}

// TestStubsReturnError confirms the stub RunE returns errStubNotImplemented.
// main.go translates a non-nil RunE error into exit-code 1, so this is the
// load-bearing assertion that `agenthound loot` fails with non-zero status.
func TestStubsReturnError(t *testing.T) {
	for _, verb := range []string{"loot", "extract", "poison", "implant"} {
		t.Run(verb, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{verb})
			if err != nil {
				t.Fatalf("rootCmd.Find(%q): %v", verb, err)
			}
			runErr := cmd.RunE(cmd, nil)
			if !errors.Is(runErr, errStubNotImplemented) {
				t.Errorf("RunE for %q returned %v, want errStubNotImplemented", verb, runErr)
			}
		})
	}
}

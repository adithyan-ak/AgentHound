package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// errStubNotImplemented is returned by reserved-verb stubs so callers can
// recognize the "not yet implemented" path. The CLI driver in main.go prints
// the user-facing message before invoking Execute(); the stub additionally
// writes a one-line redirect to stderr inside RunE for test-coverage and
// for callers that bypass main (e.g. cobra's RunE pathway from Execute).
var errStubNotImplemented = errors.New("not yet implemented")

func newStubCmd(verb, oneliner string) *cobra.Command {
	return &cobra.Command{
		Use:   verb,
		Short: fmt.Sprintf("%s — %s (not yet implemented)", verb, oneliner),
		Long: fmt.Sprintf(
			"The %q action is on the AgentHound roadmap but is not yet implemented in this release.\n"+
				"See docs/future-modules.md for the planned shape and timeline.",
			verb),
		// SilenceUsage + SilenceErrors so the user-facing message printed
		// inside RunE is the only stub-related output on stderr. main.go
		// still translates the RunE error into "Error: ..." + exit 1, so
		// the user sees exactly two lines: the friendly stub message and
		// main.go's generic error suffix.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stderr, "agenthound %s: not yet implemented — see docs/future-modules.md\n", cmd.Use)
			return errStubNotImplemented
		},
	}
}

func init() {
	rootCmd.AddCommand(newStubCmd("loot", "loot known services on a target"))
	rootCmd.AddCommand(newStubCmd("extract", "extract source data from derived artifacts"))
	rootCmd.AddCommand(newStubCmd("poison", "inject attacker-controlled artifacts"))
	rootCmd.AddCommand(newStubCmd("implant", "plant persistence in instruction or config files"))
}

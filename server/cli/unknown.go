package cli

import (
	"fmt"
	"os"
)

// collectorVerbs lists the subcommands that live in the agenthound (collector)
// binary. When the user invokes one of these against agenthound-server, we
// print a one-line redirect and exit non-zero.
var collectorVerbs = map[string]bool{
	"scan":    true,
	"collect": true,
	"setup":   true,
	"rules":   true,
	"loot":    true,
	"extract": true,
	"poison":  true,
	"implant": true,
}

// HandleUnknownCommand inspects os.Args for a top-level subcommand that lives
// in the sibling binary. If matched, it prints a redirect message and exits 1.
// Returns true if it handled the command (caller should not call Execute).
func HandleUnknownCommand() bool {
	if len(os.Args) < 2 {
		return false
	}
	verb := os.Args[1]
	if !collectorVerbs[verb] {
		return false
	}
	// Cobra still resolves real subcommands first; this only fires when verb
	// is not registered on this binary's rootCmd. Confirm by walking the tree.
	if _, _, err := rootCmd.Find(os.Args[1:]); err == nil {
		return false
	}
	fmt.Fprintf(os.Stderr,
		"%q lives in the 'agenthound' collector binary — see https://github.com/adithyan-ak/agenthound#two-binary-split\n",
		verb)
	os.Exit(1)
	return true
}

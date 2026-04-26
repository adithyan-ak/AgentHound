package cli

import (
	"fmt"
	"os"
)

// serverVerbs lists the subcommands that live in the agenthound-server
// binary. When the user invokes one against the collector, we print a
// one-line redirect and exit non-zero.
var serverVerbs = map[string]bool{
	"serve":  true,
	"ingest": true,
	"query":  true,
}

// HandleUnknownCommand inspects os.Args for a top-level subcommand that lives
// in the sibling binary. If matched and not registered on this rootCmd, it
// prints a redirect message and exits 1. Returns true if it handled the
// command (caller should not call Execute).
func HandleUnknownCommand() bool {
	if len(os.Args) < 2 {
		return false
	}
	verb := os.Args[1]
	if !serverVerbs[verb] {
		return false
	}
	if _, _, err := rootCmd.Find(os.Args[1:]); err == nil {
		return false
	}
	fmt.Fprintf(os.Stderr,
		"%q moved to the 'agenthound-server' binary — see https://github.com/adithyan-ak/agenthound#two-binary-split\n",
		verb)
	os.Exit(1)
	return true
}

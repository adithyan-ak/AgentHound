package main

import (
	"fmt"
	"os"

	"github.com/adithyan-ak/agenthound/collector/cli"

	// Blank-import modules so their init() registers them with sdk/module.
	_ "github.com/adithyan-ak/agenthound/modules/a2a"
	_ "github.com/adithyan-ak/agenthound/modules/config"
	_ "github.com/adithyan-ak/agenthound/modules/mcp"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	cli.SetVersion(version, commit)
	if cli.HandleUnknownCommand() {
		return
	}
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

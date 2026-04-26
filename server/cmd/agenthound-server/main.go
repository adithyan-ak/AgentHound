package main

import (
	"fmt"
	"os"

	"github.com/adithyan-ak/agenthound/server/cli"
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

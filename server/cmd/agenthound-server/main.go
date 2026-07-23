package main

import (
	"fmt"
	"os"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/cli"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	version, commit = common.ResolveBuildInfo(version, commit)
	cli.SetVersion(version, commit)
	if cli.HandleUnknownCommand() {
		return
	}
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

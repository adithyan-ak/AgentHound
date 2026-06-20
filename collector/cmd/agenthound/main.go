package main

import (
	"fmt"
	"os"

	"github.com/adithyan-ak/agenthound/collector/cli"

	// Blank-import modules so their init() registers them with sdk/module.
	_ "github.com/adithyan-ak/agenthound/modules/a2a"
	_ "github.com/adithyan-ak/agenthound/modules/config"
	_ "github.com/adithyan-ak/agenthound/modules/embeddinginvert"
	_ "github.com/adithyan-ak/agenthound/modules/instructionpoison"
	_ "github.com/adithyan-ak/agenthound/modules/jupyterfp"
	_ "github.com/adithyan-ak/agenthound/modules/jupyterloot"
	_ "github.com/adithyan-ak/agenthound/modules/langservefp"
	_ "github.com/adithyan-ak/agenthound/modules/litellmfp"
	_ "github.com/adithyan-ak/agenthound/modules/litellmloot"
	_ "github.com/adithyan-ak/agenthound/modules/mcp"
	_ "github.com/adithyan-ak/agenthound/modules/mcpconfigimplant"
	_ "github.com/adithyan-ak/agenthound/modules/mcppoison"
	_ "github.com/adithyan-ak/agenthound/modules/mlflowfp"
	_ "github.com/adithyan-ak/agenthound/modules/mlflowloot"
	_ "github.com/adithyan-ak/agenthound/modules/networkscan"
	_ "github.com/adithyan-ak/agenthound/modules/ollamafp"
	_ "github.com/adithyan-ak/agenthound/modules/ollamaloot"
	_ "github.com/adithyan-ak/agenthound/modules/openwebuifp"
	_ "github.com/adithyan-ak/agenthound/modules/openwebuiloot"
	_ "github.com/adithyan-ak/agenthound/modules/protoscan"
	_ "github.com/adithyan-ak/agenthound/modules/qdrantfp"
	_ "github.com/adithyan-ak/agenthound/modules/qdrantloot"
	_ "github.com/adithyan-ak/agenthound/modules/vllmfp"
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

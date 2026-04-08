package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var collectMCPCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Enumerate MCP servers and collect tool/resource data",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("MCP collector not yet implemented (Phase 2)")
		return nil
	},
}

func init() {
	collectMCPCmd.Flags().Bool("discover", false, "Discover all configured MCP servers")
	collectMCPCmd.Flags().String("config", "", "Path to MCP client config file")
	collectMCPCmd.Flags().String("url", "", "URL of a single HTTP MCP server")
	collectCmd.AddCommand(collectMCPCmd)
}

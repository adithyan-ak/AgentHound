package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect data from MCP servers, A2A agents, or config files",
}

var collectConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Parse MCP client configuration files",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Config collector not yet implemented (Phase 2)")
		return nil
	},
}

func init() {
	collectConfigCmd.Flags().Bool("discover", false, "Discover all MCP client config files")
	collectConfigCmd.Flags().String("path", "", "Path to specific config file")
	collectCmd.AddCommand(collectConfigCmd)
	rootCmd.AddCommand(collectCmd)
}

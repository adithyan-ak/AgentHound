package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Execute Cypher queries against the graph",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Query CLI not yet implemented (Phase 3)")
		return nil
	},
}

func init() {
	queryCmd.Flags().String("prebuilt", "", "Run a pre-built query by ID")
	queryCmd.Flags().Bool("findings", false, "List all findings")
	queryCmd.Flags().String("severity", "", "Filter by severity: critical, high, medium, low")
	rootCmd.AddCommand(queryCmd)
}

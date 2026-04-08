package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var collectA2ACmd = &cobra.Command{
	Use:   "a2a",
	Short: "Fetch A2A Agent Cards and collect skill data",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("A2A collector not yet implemented (Phase 2)")
		return nil
	},
}

func init() {
	collectA2ACmd.Flags().String("target", "", "URL of a single A2A agent")
	collectA2ACmd.Flags().StringSlice("targets", nil, "URLs of multiple A2A agents")
	collectCmd.AddCommand(collectA2ACmd)
}

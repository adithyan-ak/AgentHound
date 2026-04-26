package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/spf13/cobra"
)

var ingestCmd = &cobra.Command{
	Use:   "ingest <file.json>",
	Short: "Ingest collector JSON output into the graph database",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		var ingestData ingest.IngestData
		if err := json.Unmarshal(data, &ingestData); err != nil {
			return fmt.Errorf("parse JSON: %w", err)
		}

		infra, cleanup, err := Bootstrap(ctx)
		if err != nil {
			return err
		}
		defer cleanup()

		result, err := infra.Pipeline.Ingest(ctx, &ingestData)
		if err != nil {
			return fmt.Errorf("ingest: %w", err)
		}

		fmt.Printf("Ingest complete:\n")
		fmt.Printf("  Scan ID:       %s\n", result.ScanID)
		fmt.Printf("  Nodes written: %d\n", result.NodesWritten)
		fmt.Printf("  Edges written: %d\n", result.EdgesWritten)
		fmt.Printf("  Duration:      %s\n", result.Duration)
		if len(result.Warnings) > 0 {
			fmt.Printf("  Warnings:      %d\n", len(result.Warnings))
			for _, w := range result.Warnings {
				slog.Warn(w)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(ingestCmd)
}

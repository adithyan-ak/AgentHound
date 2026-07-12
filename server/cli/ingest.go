package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/spf13/cobra"
)

var ingestCmd = &cobra.Command{
	Use:   "ingest <file.json | ->",
	Short: "Ingest collector JSON output into the graph database",
	Long: `Ingest collector JSON into the graph database.

Provide a path to a collector JSON file, or '-' to read from stdin. The
stdin form is the standard pipe target for 'agenthound scan --output -':

  agenthound scan --output - | agenthound-server ingest -
  ssh target 'agenthound scan --output -' | agenthound-server ingest -`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		filePath := args[0]

		var data []byte
		var err error
		if filePath == "-" {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
		} else {
			data, err = os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
		}

		var ingestData ingest.IngestData
		if err := ingest.DecodeStrict(bytes.NewReader(data), &ingestData); err != nil {
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
		fmt.Printf("  Node write rows: %d\n", result.WriteRows.Nodes)
		fmt.Printf("  Edge write rows: %d\n", result.WriteRows.Edges)
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

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/internal/appdb"
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/ingest"
	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/spf13/cobra"
)

var ingestCmd = &cobra.Command{
	Use:   "ingest <file.json>",
	Short: "Ingest collector JSON output into the graph database",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		filePath := args[0]

		// Read file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		// Parse JSON
		var ingestData model.IngestData
		if err := json.Unmarshal(data, &ingestData); err != nil {
			return fmt.Errorf("parse JSON: %w", err)
		}

		// Connect Neo4j
		neo4jDriver, err := graph.NewDriver(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword)
		if err != nil {
			return fmt.Errorf("neo4j: %w", err)
		}
		defer neo4jDriver.Close(ctx)

		// Connect PostgreSQL
		pgPool, err := appdb.NewPool(cfg.PostgresURI)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		defer pgPool.Close()

		// Initialize schema
		if err := graph.InitSchema(ctx, neo4jDriver); err != nil {
			return fmt.Errorf("neo4j schema: %w", err)
		}
		if err := appdb.RunMigrations(ctx, pgPool); err != nil {
			return fmt.Errorf("postgres migrations: %w", err)
		}

		// Run pipeline
		writer := graph.NewWriter(neo4jDriver)
		scanStore := appdb.NewScanStore(pgPool)
		pipeline := ingest.NewPipeline(writer, scanStore)

		result, err := pipeline.Ingest(ctx, &ingestData)
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

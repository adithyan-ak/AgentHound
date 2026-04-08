package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adithyan-ak/agenthound/internal/api"
	"github.com/adithyan-ak/agenthound/internal/appdb"
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/ingest"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the AgentHound API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Connect Neo4j
		neo4jDriver, err := graph.NewDriver(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword)
		if err != nil {
			return fmt.Errorf("neo4j: %w", err)
		}
		defer neo4jDriver.Close(ctx)
		slog.Info("connected to neo4j", "uri", cfg.Neo4jURI)

		// Connect PostgreSQL
		pgPool, err := appdb.NewPool(cfg.PostgresURI)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		defer pgPool.Close()
		slog.Info("connected to postgres")

		// Initialize schemas
		if err := graph.InitSchema(ctx, neo4jDriver); err != nil {
			return fmt.Errorf("neo4j schema: %w", err)
		}
		if err := appdb.RunMigrations(ctx, pgPool); err != nil {
			return fmt.Errorf("postgres migrations: %w", err)
		}

		// Create components
		writer := graph.NewWriter(neo4jDriver)
		reader := graph.NewReader(neo4jDriver)
		scanStore := appdb.NewScanStore(pgPool)
		pipeline := ingest.NewPipeline(writer, scanStore)
		server := api.NewServer(reader, pgPool, pipeline)

		// Graceful shutdown
		errCh := make(chan error, 1)
		go func() {
			errCh <- server.ListenAndServe(cfg.APIPort)
		}()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		select {
		case err := <-errCh:
			return err
		case sig := <-sigCh:
			slog.Info("shutting down", "signal", sig)
			shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return server.Shutdown(shutdownCtx)
		}
	},
}

func init() {
	serveCmd.Flags().Int("port", 8080, "API server port")
	rootCmd.AddCommand(serveCmd)
}

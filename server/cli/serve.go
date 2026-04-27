package cli

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/adithyan-ak/agenthound/server/internal/api"
	apimw "github.com/adithyan-ak/agenthound/server/internal/api/middleware"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the AgentHound API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		infra, cleanup, err := Bootstrap(ctx)
		if err != nil {
			return err
		}
		defer cleanup()

		rulesEngine, err := rules.NewEngine(rules.LoadOptions{})
		if err != nil {
			slog.Warn("failed to load rules engine, rules API will return empty", "error", err)
		}

		// LocalToken gates all mutating endpoints. Generated on first
		// run, persisted at ~/.agenthound/server.token (override with
		// AGENTHOUND_TOKEN_PATH). The UI fetches it from
		// /api/v1/auth/local-token.
		localToken, err := apimw.NewLocalToken("")
		if err != nil {
			return err
		}

		server := api.NewServer(api.ServerDeps{
			GraphDB:     infra.GraphDB,
			Reader:      infra.Reader,
			PGPool:      infra.PGPool,
			Pipeline:    infra.Pipeline,
			ScanStore:   infra.ScanStore,
			RulesEngine: rulesEngine,
			CORSOrigins: cfg.CORSOrigins,
			LocalToken:  localToken,
		})

		errCh := make(chan error, 1)
		go func() {
			errCh <- server.ListenAndServe(cfg.Bind)
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
	rootCmd.AddCommand(serveCmd)
}

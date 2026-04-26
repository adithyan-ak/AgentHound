package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/server/internal/servercfg"
	"github.com/spf13/cobra"
)

var cfg *servercfg.Config

var rootCmd = &cobra.Command{
	Use:   "agenthound-server",
	Short: "AgentHound ingest, analysis, and visualization server",
	Long: `AgentHound server ingests collector JSON, persists the graph in Neo4j,
runs post-processors, and serves the React UI + REST API.

Single-user posture: there is no login. The server binds to 127.0.0.1
by default; expose remotely only over your own VPN/SSH tunnel.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg = servercfg.LoadWithFlags(cmd.Root().PersistentFlags())
		if err := cfg.Validate(); err != nil {
			return err
		}
		setupLogger(cfg.LogLevel)
		return nil
	},
}

func SetVersion(version, commit string) {
	rootCmd.Version = fmt.Sprintf("%s (commit: %s)", version, commit)
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().String("log-level", "", "Log level: debug, info, warn, error (env: AGENTHOUND_LOG_LEVEL)")
	rootCmd.PersistentFlags().String("bind", "", "Bind address host:port (env: AGENTHOUND_BIND, default: 127.0.0.1:8080)")
	rootCmd.PersistentFlags().String("neo4j-uri", "", "Neo4j connection URI (env: AGENTHOUND_NEO4J_URI)")
	rootCmd.PersistentFlags().String("neo4j-user", "", "Neo4j username (env: AGENTHOUND_NEO4J_USER)")
	rootCmd.PersistentFlags().String("neo4j-password", "", "Neo4j password (env: AGENTHOUND_NEO4J_PASSWORD)")
	rootCmd.PersistentFlags().String("pg-uri", "", "PostgreSQL connection URI (env: AGENTHOUND_PG_URI)")
	rootCmd.PersistentFlags().String("cors-origins", "", "Comma-separated CORS origins (env: AGENTHOUND_CORS_ORIGINS)")
}

func setupLogger(level string) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))
}

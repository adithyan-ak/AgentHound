package cli

import (
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/internal/config"
	"github.com/spf13/cobra"
)

var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:   "agenthound",
	Short: "BloodHound for AI Agent Infrastructure",
	Long:  "AgentHound enumerates MCP servers and A2A agents, builds a directed trust graph, and discovers attack paths across protocol boundaries.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		cfg = config.LoadWithFlags(cmd.Root().PersistentFlags())
		setupLogger(cfg.LogLevel)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().String("neo4j-uri", "", "Neo4j connection URI (env: AGENTHOUND_NEO4J_URI)")
	rootCmd.PersistentFlags().String("neo4j-user", "", "Neo4j username (env: AGENTHOUND_NEO4J_USER)")
	rootCmd.PersistentFlags().String("neo4j-password", "", "Neo4j password (env: AGENTHOUND_NEO4J_PASSWORD)")
	rootCmd.PersistentFlags().String("pg-uri", "", "PostgreSQL connection URI (env: AGENTHOUND_PG_URI)")
	rootCmd.PersistentFlags().String("log-level", "", "Log level: debug, info, warn, error (env: AGENTHOUND_LOG_LEVEL)")
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

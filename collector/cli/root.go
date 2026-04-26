package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	"github.com/spf13/cobra"
)

var cfg *clientcfg.Config

var rootCmd = &cobra.Command{
	Use:   "agenthound",
	Short: "BloodHound for AI Agent Infrastructure — collector",
	Long: `AgentHound enumerates MCP servers, A2A agents, and client configurations,
then ships the trust graph as JSON to an agenthound-server (or to a file).

The collector is auth-less. Reach the server over a network you already
control: localhost, VPN, SSH tunnel.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg = clientcfg.LoadWithFlags(cmd.Root().PersistentFlags())
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
	rootCmd.PersistentFlags().String("server-url", "", "AgentHound server URL for upload mode (env: AGENTHOUND_SERVER_URL)")
	rootCmd.PersistentFlags().String("output", "", "Write collected JSON to this path instead of uploading (env: AGENTHOUND_OUTPUT)")
	rootCmd.PersistentFlags().Int("concurrency", 0, "Max parallel collector workers (env: AGENTHOUND_CONCURRENCY)")
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

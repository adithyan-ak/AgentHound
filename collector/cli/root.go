package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/spf13/cobra"
)

var cfg *clientcfg.Config

var rootCmd = &cobra.Command{
	Use:           "agenthound",
	Short:         "Autonomous offensive collector for AI agent infrastructure",
	SilenceUsage:  true,
	SilenceErrors: true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	Long: `AgentHound collects local and network evidence, captures usable
credentials, verifies reachable attack paths, and immediately restores any
temporary mutation in one scan. The result is one local JSON artifact for
optional manual ingestion with 'agenthound-server ingest <scan.json>'.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg = clientcfg.Load()
		if err := cfg.Validate(); err != nil {
			return err
		}
		quiet, _ := cmd.Flags().GetBool("quiet")
		if !quiet && os.Getenv("AGENTHOUND_QUIET") == "1" {
			quiet = true
		}
		setupLogger(cfg.LogLevel, quiet, false)
		return nil
	},
}

func SetVersion(version, commit string) {
	rootCmd.Version = fmt.Sprintf("%s (commit: %s)", version, commit)
	common.SetCollectorVersion(version)
}

func Execute() error {
	return rootCmd.Execute()
}

// quietEnabled resolves the effective quiet setting for a command: the
// --quiet local flag OR AGENTHOUND_QUIET=1, mirroring the resolution in
// PersistentPreRunE. It is safe to call on a command with no parent (the
// flag lookup simply fails and we fall back to the env var), so unit tests
// that build bare commands don't panic.
func quietEnabled(cmd *cobra.Command) bool {
	if q, err := cmd.Flags().GetBool("quiet"); err == nil && q {
		return true
	}
	return os.Getenv("AGENTHOUND_QUIET") == "1"
}

func setupLogger(level string, quiet, jsonLog bool) {
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
	if quiet {
		logLevel = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: logLevel}
	var handler slog.Handler
	if jsonLog {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

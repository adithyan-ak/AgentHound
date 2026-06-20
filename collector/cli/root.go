package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/spf13/cobra"
)

var cfg *clientcfg.Config

var rootCmd = &cobra.Command{
	Use:   "agenthound",
	Short: "BloodHound for AI Agent Infrastructure — collector",
	Long: `AgentHound enumerates MCP servers, A2A agents, and client configurations,
then writes the trust graph as JSON to a file or stdout.

The collector is auth-less and offline-by-default. Operators ingest the
resulting JSON on their analysis box via 'agenthound-server ingest <file>',
'cat scan.json | agenthound-server ingest -', or by drag-dropping into the
UI's Scan Manager → Import Scan dialog.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg = clientcfg.LoadWithFlags(cmd.Root().PersistentFlags())
		if err := cfg.Validate(); err != nil {
			return err
		}
		quiet, _ := cmd.Root().PersistentFlags().GetBool("quiet")
		jsonLog, _ := cmd.Root().PersistentFlags().GetBool("log-json")
		if !quiet && os.Getenv("AGENTHOUND_QUIET") == "1" {
			quiet = true
		}
		if !jsonLog && os.Getenv("AGENTHOUND_LOG_JSON") == "1" {
			jsonLog = true
		}
		setupLogger(cfg.LogLevel, quiet, jsonLog)

		// v0.3 — wire the rules-bundle override BEFORE any module's
		// Fingerprint() call. rules.SetBundleOverridePath is a
		// process-global so subsequent rules.LoadFingerprints() reads
		// inside fingerprinter modules see the merged set transparently.
		bundle, _ := cmd.Root().PersistentFlags().GetString("rules-bundle")
		if bundle == "" {
			bundle = os.Getenv("AGENTHOUND_RULES_BUNDLE")
		}
		if bundle != "" {
			rules.SetBundleOverridePath(bundle)
		}
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
	rootCmd.PersistentFlags().String("output", "", "Write collected JSON to this path. Use '-' for stdout. Defaults to ./scan-<scan_id>.json in CWD. (env: AGENTHOUND_OUTPUT)")
	rootCmd.PersistentFlags().Int("concurrency", 0, "Max parallel collector workers (env: AGENTHOUND_CONCURRENCY)")
	rootCmd.PersistentFlags().Bool("quiet", false, "Suppress non-error log output (env: AGENTHOUND_QUIET=1)")
	rootCmd.PersistentFlags().Bool("log-json", false, "Emit logs as JSON instead of text (env: AGENTHOUND_LOG_JSON=1)")
	rootCmd.PersistentFlags().String("rules-bundle", "", "Path to a fingerprint rules bundle (directory or .tar.gz). Same-id rules from the bundle override the embedded set. Verify cosign signature manually before pointing AgentHound at it; see https://docs.agenthound.io/reference/rule-syntax/. (env: AGENTHOUND_RULES_BUNDLE)")
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

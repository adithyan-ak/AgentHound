package cli

import (
	"context"
	"log/slog"
	"testing"

	_ "github.com/adithyan-ak/agenthound/modules/mcppoison"
	"github.com/adithyan-ak/agenthound/sdk/common"
)

func TestSetupLogger_Levels(t *testing.T) {
	tests := []struct {
		level string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			setupLogger(tt.level, false, false)
			if !slog.Default().Handler().Enabled(context.Background(), tt.want) {
				t.Errorf("setupLogger(%q): expected level %v to be enabled", tt.level, tt.want)
			}
		})
	}
}

func TestSetupLogger_QuietForcesErrorLevel(t *testing.T) {
	setupLogger("debug", true, false)
	if slog.Default().Handler().Enabled(context.Background(), slog.LevelInfo) {
		t.Error("--quiet should suppress info-level output even when log-level=debug")
	}
	if !slog.Default().Handler().Enabled(context.Background(), slog.LevelError) {
		t.Error("--quiet should still allow error-level output")
	}
}

func TestSetupLogger_JSONHandler(t *testing.T) {
	// Just verify the call path doesn't panic and the level is honored.
	setupLogger("warn", false, true)
	if !slog.Default().Handler().Enabled(context.Background(), slog.LevelWarn) {
		t.Error("expected warn level enabled with JSON handler")
	}
}

func TestSetVersion(t *testing.T) {
	previousCollectorVersion := common.CollectorVersion()
	t.Cleanup(func() { common.SetCollectorVersion(previousCollectorVersion) })
	SetVersion("1.2.3", "abc123")
	want := "1.2.3 (commit: abc123)"
	if rootCmd.Version != want {
		t.Errorf("Version = %q, want %q", rootCmd.Version, want)
	}
	if got := common.CollectorVersion(); got != "1.2.3" {
		t.Errorf("collector protocol version = %q, want 1.2.3", got)
	}
}

func TestFinalizeModuleFlagsRegistersContextForgeProductionCLI(t *testing.T) {
	finalizeModuleFlags()
	finalizeModuleFlags() // production setup is intentionally idempotent

	for _, name := range []string{"adapter", "management-url", "insecure"} {
		if poisonCmd.Flags().Lookup(name) == nil {
			t.Errorf("production poison command is missing --%s", name)
		}
	}
	for _, name := range []string{"update-method", "update-path", "list-path", "auth-token"} {
		if poisonCmd.Flags().Lookup(name) != nil {
			t.Errorf("production poison command still exposes removed --%s", name)
		}
	}
}

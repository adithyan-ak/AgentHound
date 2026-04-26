package cli

import (
	"context"
	"log/slog"
	"testing"
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
			setupLogger(tt.level)
			if !slog.Default().Handler().Enabled(context.Background(), tt.want) {
				t.Errorf("setupLogger(%q): expected level %v to be enabled", tt.level, tt.want)
			}
		})
	}
}

func TestSetVersion(t *testing.T) {
	SetVersion("1.2.3", "abc123")
	want := "1.2.3 (commit: abc123)"
	if rootCmd.Version != want {
		t.Errorf("Version = %q, want %q", rootCmd.Version, want)
	}
}

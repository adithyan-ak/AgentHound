package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestWarnIfNonLoopbackBind covers the bind classification matrix:
// loopback → silent, unspecified (Docker pattern) → info, specific
// non-loopback → warn. Fragile-looking slog capture is fine here: we
// only assert level + presence of substring, not exact formatting.
func TestWarnIfNonLoopbackBind(t *testing.T) {
	cases := []struct {
		bind         string
		wantLevel    slog.Level // -1 sentinel means "no log emitted"
		wantContains string
	}{
		{"127.0.0.1:8080", -1, ""},
		{"localhost:8080", -1, ""},
		{"[::1]:8080", -1, ""},
		{":8080", slog.LevelInfo, "all interfaces"},
		{"0.0.0.0:8080", slog.LevelInfo, "all interfaces"},
		{"[::]:8080", slog.LevelInfo, "all interfaces"},
		{"192.168.1.10:8080", slog.LevelWarn, "non-loopback bind"},
		{"10.0.0.5:8080", slog.LevelWarn, "non-loopback bind"},
		{"203.0.113.10:8080", slog.LevelWarn, "non-loopback bind"},
		{"bogus", -1, ""}, // SplitHostPort fails; we early-return
	}

	for _, c := range cases {
		t.Run(c.bind, func(t *testing.T) {
			buf := &bytes.Buffer{}
			h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
			prev := slog.Default()
			slog.SetDefault(slog.New(h))
			defer slog.SetDefault(prev)

			warnIfNonLoopbackBind(c.bind)

			out := buf.String()
			if c.wantLevel == -1 {
				if out != "" {
					t.Errorf("bind %q: expected no log output, got %q", c.bind, out)
				}
				return
			}
			levelStr := c.wantLevel.String()
			if !strings.Contains(out, "level="+levelStr) {
				t.Errorf("bind %q: expected level=%s in output, got %q",
					c.bind, levelStr, out)
			}
			if c.wantContains != "" && !strings.Contains(out, c.wantContains) {
				t.Errorf("bind %q: expected substring %q in output, got %q",
					c.bind, c.wantContains, out)
			}
		})
	}
}

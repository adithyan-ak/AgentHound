package cli

import (
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/collector/apiclient"
	"github.com/spf13/cobra"
)

func TestCountFindingsBySeverity(t *testing.T) {
	findings := []apiclient.Finding{
		{ID: "1", Severity: "critical"},
		{ID: "2", Severity: "high"},
		{ID: "3", Severity: "high"},
		{ID: "4", Severity: "medium"},
		{ID: "5", Severity: "low"},
		{ID: "6", Severity: "low"},
		{ID: "7", Severity: "low"},
	}
	counts := countFindingsBySeverity(findings)

	want := map[string]int{"critical": 1, "high": 2, "medium": 1, "low": 3}
	for sev, expected := range want {
		if counts[sev] != expected {
			t.Errorf("severity %q: got %d, want %d", sev, counts[sev], expected)
		}
	}
}

func TestCountFindingsBySeverity_Empty(t *testing.T) {
	counts := countFindingsBySeverity(nil)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if counts[sev] != 0 {
			t.Errorf("severity %q: got %d, want 0", sev, counts[sev])
		}
	}
}

func TestCountAtOrAbove(t *testing.T) {
	findings := []apiclient.Finding{
		{ID: "1", Severity: "critical"},
		{ID: "2", Severity: "high"},
		{ID: "3", Severity: "high"},
		{ID: "4", Severity: "medium"},
		{ID: "5", Severity: "low"},
	}
	got := countAtOrAbove(findings, severityRank["high"])
	if got != 3 {
		t.Errorf("countAtOrAbove(threshold=high): got %d, want 3", got)
	}
}

func TestCountAtOrAbove_NoneAbove(t *testing.T) {
	findings := []apiclient.Finding{
		{ID: "1", Severity: "medium"},
		{ID: "2", Severity: "medium"},
		{ID: "3", Severity: "low"},
	}
	got := countAtOrAbove(findings, severityRank["critical"])
	if got != 0 {
		t.Errorf("countAtOrAbove(threshold=critical): got %d, want 0", got)
	}
}

func TestCountAtOrAbove_AllLevels(t *testing.T) {
	findings := []apiclient.Finding{
		{ID: "1", Severity: "critical"},
		{ID: "2", Severity: "high"},
		{ID: "3", Severity: "medium"},
		{ID: "4", Severity: "low"},
	}

	tests := []struct {
		threshold string
		want      int
	}{
		{"critical", 1},
		{"high", 2},
		{"medium", 3},
		{"low", 4},
	}

	for _, tt := range tests {
		t.Run(tt.threshold, func(t *testing.T) {
			got := countAtOrAbove(findings, severityRank[tt.threshold])
			if got != tt.want {
				t.Errorf("countAtOrAbove(%s) = %d, want %d", tt.threshold, got, tt.want)
			}
		})
	}
}

func newScanCmdForTest() *cobra.Command {
	cmd := &cobra.Command{RunE: runScan}
	cmd.Flags().Bool("config", false, "")
	cmd.Flags().Bool("mcp", false, "")
	cmd.Flags().Bool("a2a", false, "")
	cmd.Flags().String("path", "", "")
	cmd.Flags().StringSlice("paths", nil, "")
	cmd.Flags().String("project-dir", "", "")
	cmd.Flags().Bool("include-credential-values", false, "")
	cmd.Flags().String("url", "", "")
	cmd.Flags().String("target", "", "")
	cmd.Flags().StringSlice("targets", nil, "")
	cmd.Flags().StringSlice("discover-domain", nil, "")
	cmd.Flags().String("targets-file", "", "")
	cmd.Flags().String("auth-token", "", "")
	cmd.Flags().Int("scan-concurrency", 5, "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().Bool("insecure", false, "")
	cmd.Flags().String("scan-output", "", "")
	cmd.Flags().String("fail-on", "", "")
	return cmd
}

func TestRunScan_ConfigWithURL(t *testing.T) {
	cmd := newScanCmdForTest()
	_ = cmd.Flags().Set("config", "true")
	_ = cmd.Flags().Set("url", "http://example.com")
	err := runScan(cmd, nil)
	if err == nil {
		t.Fatal("expected error for --url with --config")
	}
	if !strings.Contains(err.Error(), "--url requires --mcp") {
		t.Errorf("error = %q, want '--url requires --mcp'", err.Error())
	}
}

func TestRunScan_A2ANoTarget(t *testing.T) {
	cmd := newScanCmdForTest()
	_ = cmd.Flags().Set("a2a", "true")
	err := runScan(cmd, nil)
	if err == nil {
		t.Fatal("expected error for A2A without target")
	}
	if !strings.Contains(err.Error(), "A2A requires") {
		t.Errorf("error = %q, want 'A2A requires'", err.Error())
	}
}

func TestRunScan_InvalidFailOn(t *testing.T) {
	cmd := newScanCmdForTest()
	_ = cmd.Flags().Set("fail-on", "banana")
	err := runScan(cmd, nil)
	if err == nil {
		t.Fatal("expected error for invalid --fail-on")
	}
	if !strings.Contains(err.Error(), "invalid --fail-on") {
		t.Errorf("error = %q, want 'invalid --fail-on'", err.Error())
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank["critical"] != 0 {
		t.Errorf("critical rank = %d, want 0", severityRank["critical"])
	}
	if severityRank["high"] != 1 {
		t.Errorf("high rank = %d, want 1", severityRank["high"])
	}
	if severityRank["medium"] != 2 {
		t.Errorf("medium rank = %d, want 2", severityRank["medium"])
	}
	if severityRank["low"] != 3 {
		t.Errorf("low rank = %d, want 3", severityRank["low"])
	}
	if len(severityRank) != 4 {
		t.Errorf("severity rank has %d entries, want 4", len(severityRank))
	}
}

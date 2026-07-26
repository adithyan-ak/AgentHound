package cli

import (
	"strconv"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/modules/protoscan"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// joinPorts renders a port slice in the "/"-separated form used in the
// discover long-help prose (e.g. {3000,8000} -> "3000/8000").
func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, "/")
}

// TestDiscoverLongHelpMatchesDefaultPorts guards the discover long-help
// prose against drift from the actual default probe port sets. Before the
// fix the prose listed only "3000/8080/8443" for MCP and "80/443" for A2A,
// omitting 8000 (MCP) and 3000/8080 (A2A) that protoscan.DefaultMCPPorts /
// DefaultA2APorts actually probe. Deriving the expected strings from the
// constants keeps this test correct if the defaults ever change.
func TestDiscoverLongHelpMatchesDefaultPorts(t *testing.T) {
	mcp := joinPorts(protoscan.DefaultMCPPorts)
	a2a := joinPorts(protoscan.DefaultA2APorts)

	if !strings.Contains(discoverCmd.Long, mcp) {
		t.Errorf("discover long help missing MCP default ports %q\nLong:\n%s", mcp, discoverCmd.Long)
	}
	if !strings.Contains(discoverCmd.Long, a2a) {
		t.Errorf("discover long help missing A2A default ports %q\nLong:\n%s", a2a, discoverCmd.Long)
	}
}

func TestBuildDiscoverEnvelopeUsesProbeCoverage(t *testing.T) {
	for _, tt := range []struct {
		name   string
		report protoscan.ProbeReport
		want   ingest.OutcomeState
	}{
		{
			name:   "all conclusive",
			report: protoscan.ProbeReport{Total: 4, Conclusive: 4},
			want:   ingest.OutcomeComplete,
		},
		{
			name:   "mixed",
			report: protoscan.ProbeReport{Total: 4, Conclusive: 2},
			want:   ingest.OutcomePartial,
		},
		{
			name:   "nothing conclusive",
			report: protoscan.ProbeReport{Total: 4},
			want:   ingest.OutcomeFailed,
		},
		{
			name:   "zero probes",
			report: protoscan.ProbeReport{},
			want:   ingest.OutcomeFailed,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			envelope := buildDiscoverEnvelope(
				"127.0.0.1",
				nil,
				"",
				"",
				false,
				tt.report,
			)
			if envelope.Meta.Collection.State != tt.want {
				t.Fatalf("collection state = %q, want %q",
					envelope.Meta.Collection.State, tt.want)
			}
			outcome := envelope.Meta.Collection.Outcomes[0]
			if outcome.State != tt.want {
				t.Fatalf("protocol outcome = %+v, want %q", outcome, tt.want)
			}
			if tt.want != ingest.OutcomeComplete && outcome.Error == "" {
				t.Fatalf("incomplete protocol outcome lacks diagnostic: %+v", outcome)
			}
		})
	}
}

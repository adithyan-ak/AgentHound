package ingest

import "testing"

func TestProbeOutcomeState(t *testing.T) {
	tests := []struct {
		name       string
		total      int
		conclusive int
		want       OutcomeState
	}{
		{name: "all conclusive", total: 4, conclusive: 4, want: OutcomeComplete},
		{name: "mixed", total: 4, conclusive: 3, want: OutcomePartial},
		{name: "none conclusive", total: 4, conclusive: 0, want: OutcomeFailed},
		{name: "zero probes", total: 0, conclusive: 0, want: OutcomeFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProbeOutcomeState(tt.total, tt.conclusive); got != tt.want {
				t.Fatalf("ProbeOutcomeState(%d, %d) = %q, want %q",
					tt.total, tt.conclusive, got, tt.want)
			}
		})
	}
}

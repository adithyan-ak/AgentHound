package appdb

import (
	"strings"
	"testing"
)

func TestScanListOrderClause(t *testing.T) {
	tests := []struct {
		name  string
		order ScanListOrder
		want  string
	}{
		{name: "default", order: ScanListOrderStarted, want: "started_at DESC"},
		{name: "latest completion", order: ScanListOrderCompleted, want: "CASE WHEN status IN ('completed', 'completed_with_errors')"},
		{name: "latest publication", order: ScanListOrderPublished, want: "CASE WHEN publication_status = 'published'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanListOrderClause(tt.order); !strings.HasPrefix(got, tt.want) {
				t.Fatalf("scanListOrderClause(%q) = %q, want prefix %q", tt.order, got, tt.want)
			}
		})
	}
}

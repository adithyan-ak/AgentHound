package graph

import "testing"

func TestPublicNodeKindPrefersConcreteServiceLabel(t *testing.T) {
	got := publicNodeKind([]any{"AIService", "LiteLLMGateway"})
	if got != "LiteLLMGateway" {
		t.Fatalf("public kind = %q, want LiteLLMGateway", got)
	}
}

func TestPublicNodeKindExcludesInternalAndReservedLabels(t *testing.T) {
	for _, labels := range [][]any{
		{"SchemaVersion"},
		{"ResourceGroup"},
		{"TrustZone"},
	} {
		if got := publicNodeKind(labels); got != "" {
			t.Errorf("labels %v produced public kind %q", labels, got)
		}
	}
}

func TestNormalizePageArgsDoesNotCapOffset(t *testing.T) {
	limit, offset := normalizePageArgs(0, 250000, 100)
	if limit != 100 || offset != 250000 {
		t.Fatalf("page args = (%d, %d), want (100, 250000)", limit, offset)
	}
}

func TestBlastRadiusTraversalPattern(t *testing.T) {
	tests := []struct {
		direction string
		want      string
	}{
		{direction: "out", want: "-->"},
		{direction: "in", want: "<--"},
		{direction: "both", want: "--"},
		{direction: "sideways", want: "-->"},
		{direction: "", want: "-->"},
	}

	for _, tt := range tests {
		t.Run(tt.direction, func(t *testing.T) {
			if got := blastRadiusTraversalPattern(tt.direction); got != tt.want {
				t.Fatalf("traversal pattern = %q, want %q", got, tt.want)
			}
		})
	}
}

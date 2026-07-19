package ingest

import (
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestA2ASignatureTrustStatesAreCanonical(t *testing.T) {
	tests := []struct {
		status string
		source string
		trust  string
		signed bool
	}{
		{"unknown", "none", "unknown", false},
		{"unsigned", "none", "unknown", false},
		{"unsupported_version", "none", "unknown", true},
		{"malformed", "none", "unknown", true},
		{"key_unavailable", "jku", "untrusted", true},
		{"invalid", "trusted_store", "trusted", true},
		{"valid_untrusted", "jku", "untrusted", true},
		{"valid_trusted", "trusted_store", "trusted", true},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			node := sdkingest.Node{
				Kinds: []string{"A2AAgent"},
				Properties: map[string]any{
					"auth_method":                   "unknown",
					"auth_assurance":                "unknown",
					"auth_evidence":                 "unknown",
					"signature_verification_status": tt.status,
					"signature_key_source":          tt.source,
					"signature_key_trust":           tt.trust,
					"is_signed":                     tt.signed,
				},
			}
			if errors := validateCanonicalNodeProperties(node, 0); len(errors) != 0 {
				t.Fatalf("canonical signature state rejected: %+v", errors)
			}
		})
	}
}

func TestA2ASignatureTrustStateRejectsContradictoryTuple(t *testing.T) {
	tests := []struct {
		name   string
		status string
		source string
		trust  string
		signed bool
	}{
		{"unsigned with trusted key", "unsigned", "trusted_store", "trusted", false},
		{"unsigned marked signed", "unsigned", "none", "unknown", true},
		{"invalid marked unsigned", "invalid", "trusted_store", "trusted", false},
		{"jku marked trusted", "key_unavailable", "jku", "trusted", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := sdkingest.Node{
				Kinds: []string{"A2AAgent"},
				Properties: map[string]any{
					"auth_method":                   "unknown",
					"auth_assurance":                "unknown",
					"auth_evidence":                 "unknown",
					"signature_verification_status": tt.status,
					"signature_key_source":          tt.source,
					"signature_key_trust":           tt.trust,
					"is_signed":                     tt.signed,
				},
			}
			if errors := validateCanonicalNodeProperties(node, 0); len(errors) == 0 {
				t.Fatal("contradictory signature tuple was accepted")
			}
		})
	}
}

func TestA2ASignatureTrustStateRejectsLegacyStatus(t *testing.T) {
	node := sdkingest.Node{
		Kinds: []string{"A2AAgent"},
		Properties: map[string]any{
			"auth_method":                   "unknown",
			"auth_assurance":                "unknown",
			"auth_evidence":                 "unknown",
			"signature_verification_status": "verified",
			"signature_key_source":          "trusted_store",
			"signature_key_trust":           "trusted",
		},
	}
	if errors := validateCanonicalNodeProperties(node, 0); len(errors) == 0 {
		t.Fatal("legacy signature status was accepted")
	}
}

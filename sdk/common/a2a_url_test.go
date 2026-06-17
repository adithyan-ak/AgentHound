package common

import "testing"

func TestNormalizeA2ABaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"https://example.com/.well-known/agent-card.json", "https://example.com"},
		{"https://example.com/.well-known/agent.json", "https://example.com"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"  https://example.com  ", "https://example.com"},
		{"http://10.0.0.5:3000/.well-known/agent-card.json", "http://10.0.0.5:3000"},
		{"https://agent.example.com:443/.well-known/agent.json", "https://agent.example.com:443"},
	}
	for _, tt := range tests {
		if got := NormalizeA2ABaseURL(tt.input); got != tt.expected {
			t.Errorf("NormalizeA2ABaseURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

package config

import (
	"testing"

	"github.com/adithyan-ak/agenthound/internal/rules"
)

func testConfigEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.LoadOptions{})
	if err != nil {
		t.Fatalf("failed to create rules engine: %v", err)
	}
	return engine
}

func TestIsCredentialName_RulesEngine(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"OPENAI_API_KEY", true},
		{"DATABASE_PASSWORD", true},
		{"AUTH_TOKEN", true},
		{"MY_SECRET", true},
		{"CREDENTIAL_FILE", true},
		{"LOG_LEVEL", false},
		{"PORT", false},
		{"HOME", false},
		{"PATH", false},
	}

	engine := testConfigEngine(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCredentialName(tt.name, engine)
			if got != tt.want {
				t.Errorf("isCredentialName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsVaultRef_RulesEngine(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"vault://secrets/api-key", true},
		{"ssm://param/key", true},
		{"arn:aws:secretsmanager:us-east-1:123:secret:key", true},
		{"sk-abc123", false},
		{"hardcoded-value", false},
		{"$ENV_VAR", false},
	}

	engine := testConfigEngine(t)

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := isVaultRef(tt.value, engine)
			if got != tt.want {
				t.Errorf("isVaultRef(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestDetectFormat_RulesEngine(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"sk-ant-abc123xyz", "anthropic"},
		{"sk-abc123xyz", "openai"},
		{"xoxb-123-456-abc", "slack"},
		{"xoxp-123-456", "slack"},
		{"xoxs-123", "slack"},
		{"ghp_abc123def456", "github"},
		{"gho_abc123", "github"},
		{"ghs_abc123", "github"},
		{"AKIAIOSFODNN7EXAMPLE", "aws"},
		{"some-random-value", "generic"},
		{"$ENV_VAR", "generic"},
		{"vault://secret/key", "generic"},
	}

	engine := testConfigEngine(t)

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := detectFormat(tt.value, engine)
			if got != tt.want {
				t.Errorf("detectFormat(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestExtractCredentials_RulesEngine(t *testing.T) {
	env := map[string]string{
		"OPENAI_API_KEY": "sk-test1234567890abcdef",
		"DB_PASSWORD":    "mysecret",
		"HOME":           "/home/user",
		"PATH":           "/usr/bin",
	}

	engine := testConfigEngine(t)

	creds := ExtractCredentials(env, nil, "/test/config.json", false, engine)

	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	byName := make(map[string]CredentialInfo)
	for _, c := range creds {
		byName[c.Name] = c
	}

	apiKey, ok := byName["OPENAI_API_KEY"]
	if !ok {
		t.Fatal("missing OPENAI_API_KEY")
	}
	if apiKey.Format != "openai" {
		t.Errorf("OPENAI_API_KEY format = %q, want openai", apiKey.Format)
	}
	if apiKey.Type != "hardcoded" {
		t.Errorf("OPENAI_API_KEY type = %q, want hardcoded", apiKey.Type)
	}

	pw, ok := byName["DB_PASSWORD"]
	if !ok {
		t.Fatal("missing DB_PASSWORD")
	}
	if pw.Type != "hardcoded" {
		t.Errorf("DB_PASSWORD type = %q, want hardcoded", pw.Type)
	}
}

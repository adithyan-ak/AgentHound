package a2a

import (
	"encoding/json"
	"testing"

	"github.com/adithyan-ak/agenthound/internal/rules"
)

func testA2AEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.LoadOptions{})
	if err != nil {
		t.Fatalf("failed to create rules engine: %v", err)
	}
	return engine
}

func mustParseFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	data := loadFixture(t, name)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return m
}

func TestDetectVersion_V10(t *testing.T) {
	m := mustParseFixture(t, "agent_card_v10.json")
	if v := DetectVersion(m); v != "v1.0" {
		t.Errorf("expected v1.0, got %s", v)
	}
}

func TestDetectVersion_V030(t *testing.T) {
	m := mustParseFixture(t, "agent_card_v030.json")
	if v := DetectVersion(m); v != "v0.3.0" {
		t.Errorf("expected v0.3.0, got %s", v)
	}
}

func TestDetectVersion_NoAuth(t *testing.T) {
	m := mustParseFixture(t, "agent_card_no_auth.json")
	v := DetectVersion(m)
	if v != "v0.3.0" {
		t.Errorf("expected v0.3.0 for card with url field, got %s", v)
	}
}

func TestParseV030(t *testing.T) {
	engine := testA2AEngine(t)
	m := mustParseFixture(t, "agent_card_v030.json")
	card, err := parseV030(m, "testhash123", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if card.Name != "WeatherAgent" {
		t.Errorf("expected name WeatherAgent, got %s", card.Name)
	}
	if card.URL != "https://weather.example.com/a2a" {
		t.Errorf("expected URL https://weather.example.com/a2a, got %s", card.URL)
	}
	if card.Provider != "WeatherCorp" {
		t.Errorf("expected provider WeatherCorp, got %s", card.Provider)
	}
	if card.Version != "1.2.0" {
		t.Errorf("expected version 1.2.0, got %s", card.Version)
	}
	if len(card.ProtocolVersions) != 1 || card.ProtocolVersions[0] != "0.3.0" {
		t.Errorf("expected protocol version [0.3.0], got %v", card.ProtocolVersions)
	}
	if card.CardHash != "testhash123" {
		t.Errorf("expected card hash testhash123, got %s", card.CardHash)
	}
	if card.AuthMethod != "apiKey" {
		t.Errorf("expected auth method apiKey, got %s", card.AuthMethod)
	}
	if len(card.SecuritySchemes) != 1 {
		t.Fatalf("expected 1 security scheme, got %d", len(card.SecuritySchemes))
	}
	if card.SecuritySchemes[0].Type != "apiKey" {
		t.Errorf("expected scheme type apiKey, got %s", card.SecuritySchemes[0].Type)
	}
	if len(card.Skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(card.Skills))
	}

	skill := card.Skills[0]
	if skill.ID != "get-weather" {
		t.Errorf("expected skill ID get-weather, got %s", skill.ID)
	}
	if skill.Name != "GetWeather" {
		t.Errorf("expected skill name GetWeather, got %s", skill.Name)
	}
	if len(skill.InputModes) != 1 || skill.InputModes[0] != "application/json" {
		t.Errorf("expected input modes [application/json], got %v", skill.InputModes)
	}
	if skill.DescriptionHash == "" {
		t.Error("expected non-empty description hash")
	}
	if skill.HasInjection {
		t.Error("expected no injection patterns in clean skill")
	}
}

func TestParseV10(t *testing.T) {
	engine := testA2AEngine(t)
	m := mustParseFixture(t, "agent_card_v10.json")
	card, err := parseV10(m, "v10hash", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if card.Name != "DataAnalyst" {
		t.Errorf("expected name DataAnalyst, got %s", card.Name)
	}
	if card.URL != "https://analyst.example.com/a2a" {
		t.Errorf("expected URL from supportedInterfaces, got %s", card.URL)
	}
	if card.Provider != "AnalyticsCo" {
		t.Errorf("expected provider AnalyticsCo, got %s", card.Provider)
	}
	if len(card.ProtocolVersions) != 1 || card.ProtocolVersions[0] != "1.0" {
		t.Errorf("expected protocol version [1.0], got %v", card.ProtocolVersions)
	}
	if card.AuthMethod != "oauth" {
		t.Errorf("expected auth method oauth, got %s", card.AuthMethod)
	}
	if len(card.Skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(card.Skills))
	}

	skill := card.Skills[0]
	if skill.ID != "analyze-data" {
		t.Errorf("expected skill ID analyze-data, got %s", skill.ID)
	}
	if len(skill.InputModes) != 2 {
		t.Errorf("expected 2 input modes, got %d", len(skill.InputModes))
	}
	if len(skill.OutputModes) != 2 {
		t.Errorf("expected 2 output modes, got %d", len(skill.OutputModes))
	}
}

func TestParseV030_NoAuth(t *testing.T) {
	engine := testA2AEngine(t)
	m := mustParseFixture(t, "agent_card_no_auth.json")
	card, err := parseV030(m, "noauthhash", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if card.AuthMethod != "none" {
		t.Errorf("expected auth method none, got %s", card.AuthMethod)
	}
	if len(card.SecuritySchemes) != 0 {
		t.Errorf("expected 0 security schemes, got %d", len(card.SecuritySchemes))
	}
	if len(card.Skills) != 1 {
		t.Fatalf("expected 1 skill, got %d", len(card.Skills))
	}
}

func TestParseV030_MissingName(t *testing.T) {
	engine := testA2AEngine(t)
	raw := map[string]any{
		"url":         "https://example.com",
		"description": "no name",
	}
	_, err := parseV030(raw, "hash", engine)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestParseV10_MissingName(t *testing.T) {
	engine := testA2AEngine(t)
	raw := map[string]any{
		"supportedInterfaces": []any{},
	}
	_, err := parseV10(raw, "hash", engine)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestParseAgentCard_Dispatch(t *testing.T) {
	engine := testA2AEngine(t)
	tests := []struct {
		fixture  string
		version  string
		wantName string
	}{
		{"agent_card_v030.json", "v0.3.0", "WeatherAgent"},
		{"agent_card_v10.json", "v1.0", "DataAnalyst"},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			data := loadFixture(t, tt.fixture)
			var parsed map[string]any
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("parse: %v", err)
			}

			raw := &RawCard{
				URL:      "https://example.com",
				Body:     data,
				Parsed:   parsed,
				Version:  DetectVersion(parsed),
				CardHash: "abc123",
			}
			card, err := ParseAgentCard(raw, engine)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if card.Name != tt.wantName {
				t.Errorf("expected name %s, got %s", tt.wantName, card.Name)
			}
		})
	}
}

func TestParseV030_SignedCard(t *testing.T) {
	engine := testA2AEngine(t)
	m := mustParseFixture(t, "agent_card_signed.json")
	card, err := parseV030(m, "signedhash", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if card.Name != "SecureAgent" {
		t.Errorf("expected name SecureAgent, got %s", card.Name)
	}
	if card.AuthMethod != "mtls" {
		t.Errorf("expected auth method mtls, got %s", card.AuthMethod)
	}
}

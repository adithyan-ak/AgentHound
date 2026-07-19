package config

import (
	"net/url"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

func testCredEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.LoadOptions{})
	if err != nil {
		t.Fatalf("failed to create rules engine: %v", err)
	}
	return engine
}

func TestExtractCredentials_EnvVars(t *testing.T) {
	engine := testCredEngine(t)
	env := map[string]string{
		"OPENAI_API_KEY": "sk-test1234567890abcdef",
		"PGHOST":         "localhost",
		"DB_PASSWORD":    "mysecret",
	}

	creds := ExtractCredentials(env, nil, "/test/config.json", false, engine)
	if len(creds) != 2 {
		t.Fatalf("expected 2 creds (KEY and PASSWORD match), got %d", len(creds))
	}

	byName := make(map[string]CredentialInfo)
	for _, c := range creds {
		byName[c.Name] = c
	}

	apiKey, ok := byName["OPENAI_API_KEY"]
	if !ok {
		t.Fatal("missing OPENAI_API_KEY credential")
	}
	if apiKey.Format != "openai" {
		t.Errorf("format = %q, want %q", apiKey.Format, "openai")
	}
	if apiKey.Type != "hardcoded" {
		t.Errorf("type = %q, want %q", apiKey.Type, "hardcoded")
	}
	if !apiKey.IsExposed {
		t.Error("expected IsExposed = true for hardcoded")
	}
	if apiKey.Value == "sk-test1234567890abcdef" {
		t.Error("value should be hashed when includeValues=false")
	}

	pw := byName["DB_PASSWORD"]
	if pw.Type != "hardcoded" {
		t.Errorf("password type = %q, want hardcoded", pw.Type)
	}
}

func TestExtractCredentials_Headers(t *testing.T) {
	engine := testCredEngine(t)
	headers := map[string]string{
		"Authorization": "Bearer ghp_abc123def456",
		"Content-Type":  "application/json",
	}

	creds := ExtractCredentials(nil, headers, "/test/config.json", true, engine)

	found := false
	for _, c := range creds {
		if c.Name == "Authorization" {
			found = true
			if c.Value != "ghp_abc123def456" {
				t.Error("expected credential material without the Authorization scheme")
			}
			if c.ValueHash != common.HashCredentialValue("ghp_abc123def456") {
				t.Error("Authorization value_hash must identify the reusable credential material")
			}
			if c.AuthMethod != common.AuthBearer || c.Location != "header" {
				t.Errorf("authorization evidence = method %q location %q, want bearer/header",
					c.AuthMethod, c.Location)
			}
		}
	}
	if !found {
		t.Error("expected Authorization credential to be extracted (contains AUTH)")
	}
}

func TestExtractCredentialsSkipsTrimEmptyEnvAndHeaderValues(t *testing.T) {
	engine := testCredEngine(t)
	const (
		envMaterial    = "  env-secret-with-space  "
		headerMaterial = "\theader-secret-with-space \n"
	)
	creds := ExtractCredentials(
		map[string]string{
			"EMPTY_API_KEY":        "",
			"WHITESPACE_TOKEN":     " \t\n ",
			"PRESERVED_ENV_SECRET": envMaterial,
		},
		map[string]string{
			"X-Empty-API-Key":    "",
			"X-Whitespace-Token": " \t\n ",
			"X-Preserved-Secret": headerMaterial,
		},
		"/test/config.json",
		true,
		engine,
	)
	if len(creds) != 2 {
		t.Fatalf("credentials = %d, want only two non-empty values: %+v", len(creds), creds)
	}
	byName := make(map[string]CredentialInfo, len(creds))
	for _, credential := range creds {
		byName[credential.Name] = credential
	}
	for _, test := range []struct {
		name, location, material string
	}{
		{name: "PRESERVED_ENV_SECRET", location: "env", material: envMaterial},
		{name: "X-Preserved-Secret", location: "header", material: headerMaterial},
	} {
		credential, ok := byName[test.name]
		if !ok {
			t.Errorf("missing non-empty credential %q: %+v", test.name, creds)
			continue
		}
		if credential.Location != test.location || credential.Value != test.material {
			t.Errorf(
				"%s = location %q value %q, want %q and exact raw material %q",
				test.name,
				credential.Location,
				credential.Value,
				test.location,
				test.material,
			)
		}
		if credential.ValueHash != common.HashCredentialValue(test.material) {
			t.Errorf("%s value_hash did not preserve surrounding whitespace", test.name)
		}
	}
}

func TestExtractArgumentCredentialsSkipsTrimEmptyValues(t *testing.T) {
	engine := testCredEngine(t)
	const material = "  argument-secret-with-space  "
	creds := extractArgumentCredentials([]string{
		"--api-key=",
		"--token", " \t ",
		"--client-secret=" + material,
	}, "test", true, engine)
	if len(creds) != 1 {
		t.Fatalf("argument credentials = %d, want one non-empty value: %+v", len(creds), creds)
	}
	if creds[0].Name != "CLIENT_SECRET" || creds[0].Location != "arg:3" ||
		creds[0].Value != material ||
		creds[0].ValueHash != common.HashCredentialValue(material) {
		t.Fatalf("non-empty argument material was not byte-preserved: %+v", creds[0])
	}
}

func TestExtractURLCredentialsSkipsTrimEmptyValues(t *testing.T) {
	engine := testCredEngine(t)
	const material = " query-secret-with-space "
	rawURL := "https://mcp.example/mcp?api_key=&token=%20%09&client_secret=" +
		url.QueryEscape(material)
	creds := extractURLCredentials(rawURL, "test", "url", true, engine)
	if len(creds) != 1 {
		t.Fatalf("URL credentials = %d, want one non-empty value: %+v", len(creds), creds)
	}
	if creds[0].Name != "CLIENT_SECRET" || creds[0].Location != "url:query:0" ||
		creds[0].Value != material ||
		creds[0].ValueHash != common.HashCredentialValue(material) {
		t.Fatalf("non-empty URL material was not byte-preserved: %+v", creds[0])
	}
}

func TestExtractURLCredentialsFallsBackToNonEmptyUsername(t *testing.T) {
	engine := testCredEngine(t)
	creds := extractURLCredentials(
		"https://user:%20%20@mcp.example/mcp",
		"test",
		"url",
		true,
		engine,
	)
	if len(creds) != 1 || creds[0].Name != "URL_USERINFO" || creds[0].Value != "user" {
		t.Fatalf("whitespace password hid non-empty userinfo: %+v", creds)
	}
}

func TestCredentialMaterialPreservesUnknownAuthorizationScheme(t *testing.T) {
	const value = "Token custom-material"
	if got := credentialMaterial("Authorization", value, "header"); got != value {
		t.Fatalf("custom authorization material = %q, want exact %q", got, value)
	}
	if got := credentialMaterial("Authorization", "  Bearer   abc123  ", "header"); got != "abc123" {
		t.Fatalf("Bearer material = %q, want abc123", got)
	}
}

func TestExtractCredentials_IncludeValues(t *testing.T) {
	engine := testCredEngine(t)
	env := map[string]string{
		"SECRET_KEY": "mysecretvalue",
	}

	creds := ExtractCredentials(env, nil, "/test", true, engine)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Value != "mysecretvalue" {
		t.Errorf("value = %q, want raw value", creds[0].Value)
	}
}

func TestExtractCredentials_HashByDefault(t *testing.T) {
	engine := testCredEngine(t)
	env := map[string]string{
		"API_KEY": "testvalue",
	}

	creds := ExtractCredentials(env, nil, "/test", false, engine)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}

	expected := common.HashSHA256("testvalue")
	if creds[0].Value != expected {
		t.Errorf("value = %q, want SHA-256 hash %q", creds[0].Value, expected)
	}
}

func TestClassifyCredentialType(t *testing.T) {
	engine := testCredEngine(t)
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"env ref $", "$MY_SECRET", "envVar"},
		{"env ref ${}", "${MY_SECRET}", "envVar"},
		{"vault ref", "vault://secrets/api-key", "vaultRef"},
		{"ssm ref", "ssm://param/key", "vaultRef"},
		{"aws secretsmanager", "arn:aws:secretsmanager:us-east-1:123:secret:key", "vaultRef"},
		{"plain hardcoded", "abc123", "hardcoded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCredentialType("SOME_KEY", tt.value, engine)
			if got != tt.want {
				t.Errorf("classifyCredentialType(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	engine := testCredEngine(t)
	tests := []struct {
		value string
		want  string
	}{
		{"sk-abc123", "openai"},
		{"sk-ant-abc123", "anthropic"},
		{"xoxb-123-456", "slack"},
		{"xoxp-123", "slack"},
		{"xoxs-123", "slack"},
		{"ghp_abc123", "github"},
		{"gho_abc123", "github"},
		{"ghs_abc123", "github"},
		{"AKIAIOSFODNN7EXAMPLE", "aws"},
		{"some-random-value", "generic"},
		{"$ENV_VAR", "generic"},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := detectFormat(tt.value, engine)
			if got != tt.want {
				t.Errorf("detectFormat(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestExtractCredentials_EnvRefNotExposed(t *testing.T) {
	engine := testCredEngine(t)
	env := map[string]string{
		"API_TOKEN": "$REAL_TOKEN",
	}

	creds := ExtractCredentials(env, nil, "/test", false, engine)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Type != "envVar" {
		t.Errorf("type = %q, want envVar", creds[0].Type)
	}
	if creds[0].IsExposed {
		t.Error("envVar ref should not be exposed")
	}
	if creds[0].MaterialStatus != common.CredentialMaterialUnobserved ||
		creds[0].ExposureStatus != common.CredentialExposureNotObserved {
		t.Errorf("env ref evidence = material %q exposure %q",
			creds[0].MaterialStatus, creds[0].ExposureStatus)
	}
}

func TestExtractCredentials_VaultRefNotExposed(t *testing.T) {
	engine := testCredEngine(t)
	env := map[string]string{
		"SECRET_KEY": "vault://secrets/mykey",
	}

	creds := ExtractCredentials(env, nil, "/test", false, engine)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Type != "vaultRef" {
		t.Errorf("type = %q, want vaultRef", creds[0].Type)
	}
	if creds[0].IsExposed {
		t.Error("vaultRef should not be exposed")
	}
}

func TestExtractCredentials_AuthSchemes(t *testing.T) {
	engine := testCredEngine(t)
	tests := []struct {
		name   string
		env    map[string]string
		head   map[string]string
		method common.AuthMethod
	}{
		{"x api key", nil, map[string]string{"X-API-Key": "secret-value"}, common.AuthAPIKey},
		{"basic", nil, map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}, common.AuthBasic},
		{"custom authorization", nil, map[string]string{"Authorization": "Token abcdefgh"}, common.AuthCustom},
		{"oauth env", map[string]string{"OAUTH_CLIENT_ID": "client-id"}, nil, common.AuthOAuth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := ExtractCredentials(tt.env, tt.head, "test", false, engine)
			if len(creds) != 1 {
				t.Fatalf("credentials = %d, want 1: %+v", len(creds), creds)
			}
			if creds[0].AuthMethod != tt.method {
				t.Fatalf("auth method = %q, want %q", creds[0].AuthMethod, tt.method)
			}
		})
	}
}

func TestExtractCredentials_NonCredentialNamesSkipped(t *testing.T) {
	engine := testCredEngine(t)
	env := map[string]string{
		"HOME":       "/home/user",
		"PATH":       "/usr/bin",
		"TERM":       "xterm",
		"API_KEY":    "val1",
		"MY_SECRET":  "val2",
		"AUTH_TOKEN": "val3",
	}

	creds := ExtractCredentials(env, nil, "/test", false, engine)
	names := make(map[string]bool)
	for _, c := range creds {
		names[c.Name] = true
	}

	if names["HOME"] || names["PATH"] || names["TERM"] {
		t.Error("non-credential env vars should be skipped")
	}
	if !names["API_KEY"] || !names["MY_SECRET"] || !names["AUTH_TOKEN"] {
		t.Error("credential env vars should be detected")
	}
}

func TestExtractCredentials_HighEntropy(t *testing.T) {
	engine := testCredEngine(t)
	env := map[string]string{
		"API_KEY": "aB3dE6gH9jKlMnOpQrStUvWxYz012345",
	}

	creds := ExtractCredentials(env, nil, "/test", false, engine)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if !creds[0].HighEntropy {
		t.Error("expected HighEntropy for high-entropy base64-like string")
	}
}

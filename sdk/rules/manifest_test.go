package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestBuildManifestDeterministicAcrossOrderAndSourcePath(t *testing.T) {
	first := manifestTextRule("rule-a", "/tmp/a.yaml")
	second := manifestTextRule("rule-b", "/tmp/b.yaml")

	a := BuildManifest([]Rule{first, second}, nil)
	b := BuildManifest(
		[]Rule{
			manifestTextRule("rule-b", "/another/b.yaml"),
			manifestTextRule("rule-a", "/another/a.yaml"),
		},
		nil,
	)
	if a.Digest != b.Digest {
		t.Fatalf("equivalent effective rules changed digest: %s != %s", a.Digest, b.Digest)
	}
}

func TestBuildManifestChangesWithRuleSemantics(t *testing.T) {
	base := manifestTextRule("rule-a", "builtin")
	changed := base
	changed.Matcher.Pattern = "different"

	a := BuildManifest([]Rule{base}, nil)
	b := BuildManifest([]Rule{changed}, nil)
	if a.Digest == b.Digest || a.Entries[0].SemanticSHA256 == b.Entries[0].SemanticSHA256 {
		t.Fatal("semantic rule change did not change manifest digest")
	}
	if a.Authenticity != "unverified" {
		t.Fatalf("digest incorrectly claimed authenticity: %q", a.Authenticity)
	}
}

func TestBuildManifestIncludesFingerprintRules(t *testing.T) {
	fp := FingerprintRule{
		ID:          "test-fingerprint",
		Name:        "Test",
		Version:     2,
		ServiceKind: "test",
		Source:      "builtin",
		Probes: []FingerprintProbe{{
			Method: "GET",
			Path:   "/health",
			Matchers: []FingerprintMatch{{
				Type:       "http_status",
				StatusCode: 200,
			}},
		}},
		Emit: FingerprintEmit{NodeKinds: []string{"MCPServer"}},
	}
	manifest := BuildManifest(nil, []FingerprintRule{fp})
	if len(manifest.Entries) != 1 || manifest.Entries[0].Type != "fingerprint" {
		t.Fatalf("fingerprint manifest entry missing: %+v", manifest)
	}
	var matcher struct {
		Probes []struct {
			Method   string `json:"method"`
			Path     string `json:"path"`
			Matchers []struct {
				Type       string `json:"type"`
				StatusCode int    `json:"status_code"`
			} `json:"matchers"`
		} `json:"probes"`
	}
	if err := json.Unmarshal(manifest.Entries[0].EffectiveMatcher, &matcher); err != nil {
		t.Fatalf("decode canonical fingerprint matcher: %v", err)
	}
	if len(matcher.Probes) != 1 ||
		matcher.Probes[0].Method != "GET" ||
		matcher.Probes[0].Path != "/health" ||
		len(matcher.Probes[0].Matchers) != 1 ||
		matcher.Probes[0].Matchers[0].Type != "http_status" ||
		matcher.Probes[0].Matchers[0].StatusCode != 200 {
		t.Fatalf("canonical fingerprint matcher = %+v", matcher)
	}
}

func TestBuildManifestPersistsCanonicalTextMatcher(t *testing.T) {
	rule := manifestTextRule("rule-a", "builtin")
	rule.Matcher = MatcherSpec{
		Type:     "compound",
		Operator: "and",
		Matchers: []MatcherSpec{
			{
				Type:            "keyword",
				Keywords:        []string{"shell", "exec"},
				CaseInsensitive: true,
				WordBoundary:    true,
				MatchMode:       "all",
			},
			{Type: "prefix", Prefixes: []string{"sk-", "tok-"}},
			{Type: "regex", Pattern: `\bcommand\b`},
			{
				Type:      "entropy",
				Charset:   "base64",
				Threshold: 4.5,
				MinLength: 20,
			},
		},
	}
	manifest := BuildManifest([]Rule{rule}, nil)
	if len(manifest.Entries) != 1 {
		t.Fatalf("manifest entries = %+v", manifest.Entries)
	}
	raw := string(manifest.Entries[0].EffectiveMatcher)
	if !strings.Contains(raw, `"type":"compound"`) ||
		!strings.Contains(raw, `"case_insensitive":true`) ||
		!strings.Contains(raw, `"word_boundary":true`) ||
		!strings.Contains(raw, `"keywords":["shell","exec"]`) ||
		!strings.Contains(raw, `"match_mode":"all"`) ||
		!strings.Contains(raw, `"prefixes":["sk-","tok-"]`) ||
		!strings.Contains(raw, `"charset":"base64"`) ||
		!strings.Contains(raw, `"threshold":4.5`) ||
		!strings.Contains(raw, `"min_length":20`) ||
		strings.Contains(raw, `"Type"`) {
		t.Fatalf("effective matcher is not canonical lower-snake JSON: %s", raw)
	}

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var persisted sdkingest.RulesetManifest
	if err := json.Unmarshal(encoded, &persisted); err != nil {
		t.Fatalf("round-trip manifest: %v", err)
	}
	if len(persisted.Entries) != 1 ||
		string(persisted.Entries[0].EffectiveMatcher) != raw {
		t.Fatalf("persisted effective matcher = %+v", persisted.Entries)
	}
	if persisted.Authenticity != "unverified" {
		t.Fatalf("content digest claimed authenticity: %q", persisted.Authenticity)
	}
}

func TestBuildManifestIncludesSkippedCustomRuleFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, "broken.yaml"),
		[]byte("{{not yaml"),
		0o600,
	); err != nil {
		t.Fatalf("write broken rule: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "valid.yaml"),
		[]byte(`
id: custom-valid-rule
name: Custom valid rule
version: 1
severity: medium
scope:
  collector: mcp
  targets: [tool.description]
matcher:
  type: keyword
  keywords: [custom]
emit:
  finding_type: custom
`),
		0o600,
	); err != nil {
		t.Fatalf("write valid rule: %v", err)
	}

	engine, err := NewEngine(LoadOptions{CustomDir: dir})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	manifest := BuildManifest(engine.Rules(), nil, engine.LoadFailures()...)
	if manifest.LoadState != sdkingest.OutcomePartial {
		t.Fatalf("manifest load state = %q, want partial", manifest.LoadState)
	}
	if len(manifest.Errors) != 1 ||
		!strings.Contains(manifest.Errors[0], "broken.yaml") {
		t.Fatalf("custom load failure was not persisted: %+v", manifest.Errors)
	}
	var foundValid bool
	for _, entry := range manifest.Entries {
		if entry.ID == "custom-valid-rule" {
			foundValid = len(entry.EffectiveMatcher) > 0
		}
	}
	if !foundValid {
		t.Fatalf("valid custom matcher absent from partial manifest: %+v", manifest)
	}
}

func manifestTextRule(id, source string) Rule {
	return Rule{
		ID:      id,
		Name:    id,
		Version: 1,
		Enabled: true,
		Scope: Scope{
			Collector: "mcp",
			Targets:   []string{"tool.name"},
		},
		Severity: "medium",
		Matcher: MatcherSpec{
			Type:    "regex",
			Pattern: "test",
		},
		Emit:   EmitConfig{FindingType: "test"},
		Source: source,
	}
}

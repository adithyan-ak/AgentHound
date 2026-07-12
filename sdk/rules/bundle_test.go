package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleRuleYAML = `
id: ollama
name: Ollama (override)
description: bundle override of the embedded ollama fingerprint
version: 2
service_kind: ollama
probes:
  - method: GET
    path: /api/version
    matchers:
      - type: http_status
        status_code: 200
emit:
  node_kinds:
    - OllamaInstance
    - AIService
  properties:
    auth_method: none
    is_anonymous_loot: "true"
`

const newRuleYAML = `
id: bundle-only-rule
name: Bundle-only rule
description: not in the embedded set
version: 2
service_kind: bundle-only
probes:
  - method: GET
    path: /probe
    matchers:
      - type: http_status
        status_code: 200
emit:
  node_kinds:
    - BundleOnlyKind
`

func TestLoadFingerprintBundle_Directory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ollama.yaml"), []byte(sampleRuleYAML), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.yaml"), []byte(newRuleYAML), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	// Non-yaml files are skipped.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# ignore me"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}

	rules, err := LoadFingerprintBundle(dir)
	if err != nil {
		t.Fatalf("LoadFingerprintBundle: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("got %d rules, want 2", len(rules))
	}
	for _, r := range rules {
		if r.Source == "" || r.Source == BundleSourceBuiltin {
			t.Errorf("rule %q has wrong Source = %q (must be the bundle path)", r.ID, r.Source)
		}
		if r.Version == 0 {
			t.Errorf("rule %q has Version = 0 (defaults should kick in)", r.ID)
		}
	}
}

func TestLoadFingerprintBundle_Tarball(t *testing.T) {
	dir := t.TempDir()
	tarballPath := filepath.Join(dir, "rules.tar.gz")

	// Build a tar.gz containing two rule files + a non-yaml entry.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for name, content := range map[string]string{
		"fingerprints/ollama.yaml": sampleRuleYAML,
		"fingerprints/bundle.yaml": newRuleYAML,
		"fingerprints/README.md":   "# ignored",
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	if err := os.WriteFile(tarballPath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	rules, err := LoadFingerprintBundle(tarballPath)
	if err != nil {
		t.Fatalf("LoadFingerprintBundle: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("got %d rules, want 2", len(rules))
	}
}

func TestLoadFingerprintBundle_MissingPath(t *testing.T) {
	_, err := LoadFingerprintBundle("/nonexistent/path/to/bundle.tar.gz")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestLoadFingerprintBundle_EmptyPath(t *testing.T) {
	_, err := LoadFingerprintBundle("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLoadFingerprintsRecordsSkippedBundleFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, "valid.yaml"),
		[]byte(newRuleYAML),
		0o600,
	); err != nil {
		t.Fatalf("write valid bundle rule: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "broken.yaml"),
		[]byte("{{not yaml"),
		0o600,
	); err != nil {
		t.Fatalf("write broken bundle rule: %v", err)
	}

	SetBundleOverridePath(dir)
	defer SetBundleOverridePath("")
	effective, err := LoadFingerprints()
	if err != nil {
		t.Fatalf("LoadFingerprints: %v", err)
	}
	failures := FingerprintLoadFailures()
	if len(failures) != 1 ||
		!strings.Contains(failures[0], "broken.yaml") {
		t.Fatalf("fingerprint load failures = %v", failures)
	}
	manifest := BuildManifest(nil, effective, failures...)
	if manifest.LoadState != "partial" ||
		len(manifest.Errors) != 1 {
		t.Fatalf("partial fingerprint manifest = %+v", manifest)
	}
}

// TestMergeFingerprintRules_OverrideSemantics asserts the load-bearing
// claim: same-id bundle rule wins over embedded rule. Without this,
// the rules-bundle loader is useless — operators can't fix broken
// embedded rules at runtime.
func TestMergeFingerprintRules_OverrideSemantics(t *testing.T) {
	base := []FingerprintRule{
		{ID: "ollama", Name: "Ollama (embedded)", ServiceKind: "ollama"},
		{ID: "litellm", Name: "LiteLLM (embedded)", ServiceKind: "litellm"},
	}
	override := []FingerprintRule{
		{ID: "ollama", Name: "Ollama (bundle hot-fix)", ServiceKind: "ollama"},
		{ID: "newkind", Name: "New service (bundle-only)", ServiceKind: "newkind"},
	}

	merged := MergeFingerprintRules(base, override)
	if len(merged) != 3 {
		t.Fatalf("merged len = %d, want 3 (embedded litellm + override ollama + bundle-only newkind)", len(merged))
	}
	byID := make(map[string]string, len(merged))
	for _, r := range merged {
		byID[r.ID] = r.Name
	}
	if got := byID["ollama"]; got != "Ollama (bundle hot-fix)" {
		t.Errorf("override didn't win: ollama.Name = %q, want bundle hot-fix", got)
	}
	if got := byID["litellm"]; got != "LiteLLM (embedded)" {
		t.Errorf("base passthrough lost: litellm.Name = %q", got)
	}
	if _, ok := byID["newkind"]; !ok {
		t.Error("bundle-only rule missing from merged set")
	}
}

func TestMergeFingerprintRules_EmptyBase(t *testing.T) {
	override := []FingerprintRule{{ID: "x", Name: "X"}}
	merged := MergeFingerprintRules(nil, override)
	if len(merged) != 1 {
		t.Errorf("got %d rules, want 1", len(merged))
	}
}

func TestMergeFingerprintRules_EmptyOverride(t *testing.T) {
	base := []FingerprintRule{{ID: "x", Name: "X"}}
	merged := MergeFingerprintRules(base, nil)
	if len(merged) != 1 {
		t.Errorf("got %d rules, want 1", len(merged))
	}
}

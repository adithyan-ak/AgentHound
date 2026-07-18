package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestManifestDigestIgnoresShadowExcludeField pins that the shadow_exclude field
// does not leak into the semantic digest of an unrelated rule, so adding the
// field cannot spuriously flip every text rule's digest across an upgrade.
func TestManifestDigestIgnoresShadowExcludeField(t *testing.T) {
	base := Rule{
		ID:      "credential-x",
		Version: 1,
		Enabled: true,
		Scope:   Scope{Collector: "mcp", Targets: []string{"credential.value"}},
		Emit:    EmitConfig{FindingType: "has_credential"},
		Matcher: MatcherSpec{Type: "regex", Pattern: "sk-[a-z]+"},
	}
	withFlag := base
	withFlag.ShadowExclude = true

	if got, want := semanticDigest(ruleForDigest(withFlag)), semanticDigest(ruleForDigest(base)); got != want {
		t.Fatalf("shadow_exclude changed a non-injection rule's digest: %s vs %s", got, want)
	}
	payload, _ := json.Marshal(ruleForDigest(base))
	if strings.Contains(string(payload), "ShadowExclude") {
		t.Fatalf("digest payload leaks ShadowExclude: %s", payload)
	}
}

// TestMergeInstructionMatchesDedupsOverlap pins that a shadow match overlapping
// a raw match of the same rule is deduped, so one underlying injection cannot
// produce two overlapping findings.
func TestMergeInstructionMatchesDedupsOverlap(t *testing.T) {
	e := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "ovl.yaml",
		id:       "ovl-rule",
		yaml:     canonicalRuleYAML("ovl-rule", "config", `ign\w+`, "has_injection_patterns"),
	})
	// Raw `ign\w+` matches "ignore" [0,6] (the ZWSP stops \w). The shadow removes
	// the ZWSP, matches "ignorenow", and projects back to [0,12] — an overlapping
	// duplicate. Only the raw match should survive.
	got := e.Evaluate("config", "instruction.content", "ignore\u200bnow")
	if len(got) != 1 {
		t.Fatalf("overlapping duplicate not deduped: got %d matches %+v", len(got), got)
	}
	if got[0].Offset != 0 {
		t.Fatalf("raw match should win, offset = %d want 0", got[0].Offset)
	}

	// Guard: two genuinely distinct (non-overlapping) occurrences are both kept.
	two := e.Evaluate("config", "instruction.content", "ignore foo ignbar")
	if len(two) != 2 {
		t.Fatalf("distinct non-overlapping matches wrongly merged: got %d %+v", len(two), two)
	}
}

// TestMergeInstructionMatchesHighVolume guards dedup correctness and near-linear
// cost: a single-char rule matches every byte in both raw and shadow, so every
// shadow match exactly duplicates a raw match and must be dropped. An O(n^2)
// dedup would not complete this in reasonable time.
func TestMergeInstructionMatchesHighVolume(t *testing.T) {
	e := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "wide.yaml",
		id:       "wide-rule",
		yaml:     canonicalRuleYAML("wide-rule", "config", `\w`, "has_injection_patterns"),
	})
	// ~200k word chars, with one zero-width char to force the shadow path.
	input := strings.Repeat("a", 200_000) + "\u200b" + strings.Repeat("b", 200_000)
	got := e.Evaluate("config", "instruction.content", input)
	// Raw matches every word char once; every shadow match exactly duplicates a
	// raw span, so nothing is appended. Result == raw match count (400k).
	if len(got) != 400_000 {
		t.Fatalf("dedup produced %d matches, want 400000 (all shadow spans are exact dups)", len(got))
	}
}

// TestShadowExcludeExitsCanonicalizationEligibility pins that a shadow-excluded
// rule is not treated as canonicalization-eligible, so the digest/RunTests gate
// mirrors the engine's actual shadow gate (which skips excluded rules).
func TestShadowExcludeExitsCanonicalizationEligibility(t *testing.T) {
	rule := Rule{
		Emit:          EmitConfig{FindingType: "has_injection_patterns"},
		Scope:         Scope{Collector: "all", Targets: []string{"instruction.content"}},
		ShadowExclude: true,
	}
	if ruleUsesInstructionCanonicalization(rule) {
		t.Fatal("shadow-excluded rule must not be canonicalization-eligible")
	}
	// The same rule without the flag stays eligible.
	rule.ShadowExclude = false
	if !ruleUsesInstructionCanonicalization(rule) {
		t.Fatal("non-excluded injection rule must remain canonicalization-eligible")
	}
}

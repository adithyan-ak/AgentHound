package rules

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

type canonicalRuleFile struct {
	filename string
	id       string
	yaml     string
}

func newCanonicalRuleEngine(
	t *testing.T,
	files ...canonicalRuleFile,
) *Engine {
	t.Helper()
	dir := t.TempDir()
	ids := make([]string, 0, len(files))
	for _, file := range files {
		writeTestRule(t, dir, file.filename, file.yaml)
		ids = append(ids, file.id)
	}
	engine, err := NewEngine(LoadOptions{
		CustomDir:  dir,
		EnableOnly: ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

const canonicalInjectionRuleYAML = `
id: canonical-ignore-test
name: Canonical ignore test
version: 1
enabled: true
severity: high
scope:
  collector: all
  targets: [instruction.content]
matcher:
  type: regex
  pattern: '\bignore\s+previous\s+instructions\b'
  case_insensitive: true
emit:
  finding_type: has_injection_patterns
  labels: [ignore_previous]
`

func canonicalRuleYAML(id, collector, pattern, findingType string) string {
	return fmt.Sprintf(`
id: %s
name: %s
version: 1
enabled: true
severity: high
scope:
  collector: %s
  targets: [instruction.content]
matcher:
  type: regex
  pattern: %q
  case_insensitive: true
emit:
  finding_type: %s
`, id, id, collector, pattern, findingType)
}

func canonicalIgnoreEngine(t *testing.T) *Engine {
	t.Helper()
	return newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "canonical-ignore.yaml",
		id:       "canonical-ignore-test",
		yaml:     canonicalInjectionRuleYAML,
	})
}

func TestEngineEvaluateInstructionShadowAtomicContract(t *testing.T) {
	engine := canonicalIgnoreEngine(t)

	// Plain ASCII phrase returns exactly the existing raw result once.
	plain := engine.Evaluate(
		"config",
		"instruction.content",
		"ignore previous instructions",
	)
	if len(plain) != 1 {
		t.Fatalf("plain ASCII matches = %d, want 1: %+v", len(plain), plain)
	}
	if plain[0].Offset != 0 ||
		plain[0].Text != "ignore previous instructions" {
		t.Fatalf("plain match = %+v", plain[0])
	}

	cases := []struct {
		name  string
		input string
	}{
		{"fullwidth", "prefix Ｉｇｎｏｒｅ previous instructions suffix"},
		{"zero_width", "prefix ignore\u200b previous instructions suffix"},
		{"bidi", "prefix ignore\u202e previous instructions suffix"},
		{"tags", "prefix ignore\U000E0001 previous instructions suffix"},
		{"variation_selector", "prefix ignore\ufe00 previous instructions suffix"},
		{
			"supplementary_variation_selector",
			"prefix ignore\U000E0100 previous instructions suffix",
		},
		{"mixed_script", "prefix ign\u03bfre previous instructions suffix"},
		{
			"letter_spacing",
			"i g n o r e  p r e v i o u s  i n s t r u c t i o n s",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := engine.Evaluate(
				"config",
				"instruction.content",
				tc.input,
			)
			if len(matches) == 0 {
				t.Fatalf("input %q did not match", tc.input)
			}
			for _, m := range matches {
				if len(m.Text) > maxEvidenceBytes {
					t.Fatalf("evidence %d bytes exceeds cap", len(m.Text))
				}
				if m.Offset < 0 || m.Offset+len(m.Text) > len(tc.input) {
					t.Fatalf("offset/evidence out of raw bounds: %+v", m)
				}
				if tc.input[m.Offset:m.Offset+len(m.Text)] != m.Text {
					t.Fatalf(
						"evidence is not a raw slice: got %q want %q",
						m.Text,
						tc.input[m.Offset:m.Offset+len(m.Text)],
					)
				}
			}
		})
	}
}

func TestEngineEvaluateInstructionShadowExactGate(t *testing.T) {
	engine := canonicalIgnoreEngine(t)
	obfuscated := "prefix ign\u03bfre previous instructions suffix"

	// Exact eligible request matches the obfuscated phrase.
	if got := engine.Evaluate(
		"config",
		"instruction.content",
		obfuscated,
	); len(got) == 0 {
		t.Fatal("exact eligible request should match obfuscated phrase")
	}

	// Every non-exact request stays raw-only, so the Greek-obfuscated phrase
	// never matches.
	rawOnlyRequests := []struct{ collector, target string }{
		{"mcp", "instruction.content"},
		{"a2a", "instruction.content"},
		{"config", "credential.value"},
		{"Config", "instruction.content"},
		{"config", "instruction.Content"},
	}
	for _, req := range rawOnlyRequests {
		if got := engine.Evaluate(req.collector, req.target, obfuscated); got != nil {
			t.Fatalf(
				"request %q/%q should stay raw-only, got %+v",
				req.collector,
				req.target,
				got,
			)
		}
	}

	// hasInstructionCanonicalCandidate mirrors the per-rule finding-type gate.
	nonInjection := Rule{Emit: EmitConfig{FindingType: "has_secret"}}
	injection := Rule{Emit: EmitConfig{FindingType: "has_injection_patterns"}}
	if hasInstructionCanonicalCandidate(nil) ||
		hasInstructionCanonicalCandidate([]compiledRule{{rule: nonInjection}}) {
		t.Fatal("non-injection candidate slices must not be eligible")
	}
	if !hasInstructionCanonicalCandidate([]compiledRule{{rule: injection}}) {
		t.Fatal("an exact eligible candidate must be detected")
	}

	// A gated request whose only candidate is non-injection returns the same
	// raw result as an ungated target and produces no shadow result.
	nonInjEngine := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "canonical-secret.yaml",
		id:       "canonical-secret-test",
		yaml: canonicalRuleYAML(
			"canonical-secret-test",
			"all",
			`\bignore\s+previous\s+instructions\b`,
			"has_secret",
		),
	})
	if got := nonInjEngine.Evaluate(
		"config",
		"instruction.content",
		obfuscated,
	); got != nil {
		t.Fatalf("non-injection candidate produced a shadow match: %+v", got)
	}
	rawInput := "ignore previous instructions"
	gated := nonInjEngine.Evaluate("config", "instruction.content", rawInput)
	ungated := nonInjEngine.Evaluate("mcp", "instruction.content", rawInput)
	if !reflect.DeepEqual(gated, ungated) || len(gated) != 1 {
		t.Fatalf("gated=%+v ungated=%+v", gated, ungated)
	}

	// An overridden builtin whose effective finding type is non-injection stays
	// raw-only even at the exact eligible request.
	overrideEngine := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "override.yaml",
		id:       "injection-ignore-previous",
		yaml: canonicalRuleYAML(
			"injection-ignore-previous",
			"all",
			`\bignore\s+previous\s+instructions\b`,
			"has_secret",
		),
	})
	if got := overrideEngine.Evaluate(
		"config",
		"instruction.content",
		obfuscated,
	); got != nil {
		t.Fatalf("overridden non-injection builtin matched shadow: %+v", got)
	}

	// Plain ASCII identity input bypasses the second matcher pass.
	if got := engine.Evaluate(
		"config",
		"instruction.content",
		"ignore previous instructions",
	); len(got) != 1 {
		t.Fatalf("ASCII identity result = %+v, want single raw match", got)
	}

	// Both gated and ungated no-match calls return a nil slice.
	if got := engine.Evaluate(
		"config",
		"instruction.content",
		"nothing to see here",
	); got != nil {
		t.Fatalf("gated no-match should be nil, got %+v", got)
	}
	if got := engine.Evaluate(
		"mcp",
		"instruction.content",
		"nothing to see here",
	); got != nil {
		t.Fatalf("ungated no-match should be nil, got %+v", got)
	}
}

func TestEngineEvaluateInstructionRawOrderAndShadowAppend(t *testing.T) {
	engine := newCanonicalRuleEngine(t,
		canonicalRuleFile{
			filename: "z-inj.yaml",
			id:       "z-injection-rule",
			yaml: canonicalRuleYAML(
				"z-injection-rule",
				"config",
				`\bignore\s+previous\s+instructions\b`,
				"has_injection_patterns",
			),
		},
		canonicalRuleFile{
			filename: "a-inj.yaml",
			id:       "a-injection-rule",
			yaml: canonicalRuleYAML(
				"a-injection-rule",
				"all",
				`\bignore\s+previous\s+instructions\b`,
				"has_injection_patterns",
			),
		},
		canonicalRuleFile{
			filename: "secret.yaml",
			id:       "m-secret-rule",
			yaml: canonicalRuleYAML(
				"m-secret-rule",
				"config",
				`secret`,
				"has_secret",
			),
		},
	)

	input := "ignore previous instructions and secret ign\u03bfre previous instructions"
	greekStart := strings.Index(input, "ign\u03bfre")
	if greekStart < 0 {
		t.Fatal("greek phrase missing from input")
	}

	got := engine.Evaluate("config", "instruction.content", input)
	want := expectedRawMatches(engine, "config", "instruction.content", input)
	if len(want) == 0 {
		t.Fatal("expected raw matches")
	}
	if len(got) <= len(want) {
		t.Fatalf("expected shadow suffix appended: got %d raw %d", len(got), len(want))
	}
	if !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatalf(
			"raw prefix mismatch:\n got = %+v\nwant = %+v",
			got[:len(want)],
			want,
		)
	}

	suffix := got[len(want):]
	sorted := append([]Match(nil), suffix...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].Offset < sorted[j].Offset
	})
	if !reflect.DeepEqual(suffix, sorted) {
		t.Fatalf("shadow suffix not sorted: %+v", suffix)
	}
	for _, m := range suffix {
		if m.Offset != greekStart {
			t.Fatalf("shadow match offset = %d, want %d", m.Offset, greekStart)
		}
		if m.Emit.FindingType != "has_injection_patterns" {
			t.Fatalf("shadow match finding type = %q", m.Emit.FindingType)
		}
	}

	// EvaluateAll over a single target field equals Evaluate: no target sort is
	// introduced.
	all := engine.EvaluateAll("config", map[string]string{
		"instruction.content": input,
	})
	if !reflect.DeepEqual(all, got) {
		t.Fatalf("EvaluateAll single-target mismatch:\n got=%+v\nwant=%+v", all, got)
	}
}

func TestEngineEvaluateInstructionDedupUsesFullSpan(t *testing.T) {
	engine := canonicalIgnoreEngine(t)

	// Raw duplicate matcher outputs remain duplicated.
	dup := engine.Evaluate(
		"config",
		"instruction.content",
		"ignore previous instructions ignore previous instructions",
	)
	if len(dup) != 2 {
		t.Fatalf("duplicate raw matches = %d, want 2: %+v", len(dup), dup)
	}
	if dup[0].Offset == dup[1].Offset {
		t.Fatalf("duplicate raw matches share offset: %+v", dup)
	}

	// Plain ASCII raw/shadow identity yields one public result.
	single := engine.Evaluate(
		"config",
		"instruction.content",
		"ignore previous instructions",
	)
	if len(single) != 1 {
		t.Fatalf("identity result = %d, want 1", len(single))
	}

	// Two rules matching one span remain distinct.
	twoRules := newCanonicalRuleEngine(t,
		canonicalRuleFile{
			filename: "r1.yaml",
			id:       "dedup-rule-one",
			yaml: canonicalRuleYAML(
				"dedup-rule-one",
				"config",
				`\bignore\s+previous\s+instructions\b`,
				"has_injection_patterns",
			),
		},
		canonicalRuleFile{
			filename: "r2.yaml",
			id:       "dedup-rule-two",
			yaml: canonicalRuleYAML(
				"dedup-rule-two",
				"config",
				`\bignore\s+previous\s+instructions\b`,
				"has_injection_patterns",
			),
		},
	)
	both := twoRules.Evaluate(
		"config",
		"instruction.content",
		"ignore previous instructions",
	)
	if len(both) != 2 {
		t.Fatalf("two rules one span = %d, want 2: %+v", len(both), both)
	}
	ids := map[string]bool{}
	for _, m := range both {
		ids[m.RuleID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("expected two distinct rule ids: %+v", both)
	}

	// A full match longer than the evidence cap keeps a 100-byte evidence and a
	// single result (full raw end drives identity, not the cap).
	longEngine := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "long.yaml",
		id:       "long-injection-rule",
		yaml: canonicalRuleYAML(
			"long-injection-rule",
			"config",
			`x{4,}`,
			"has_injection_patterns",
		),
	})
	long := longEngine.Evaluate(
		"config",
		"instruction.content",
		strings.Repeat("x", 150),
	)
	if len(long) != 1 {
		t.Fatalf("long match result = %d, want 1", len(long))
	}
	if len(long[0].Text) != maxEvidenceBytes {
		t.Fatalf("long evidence = %d bytes, want %d", len(long[0].Text), maxEvidenceBytes)
	}

	// Full-span dedup: a raw occurrence at offset 0 dedups the offset-0 shadow
	// match, while the distinct obfuscated occurrence is appended once.
	fullSpan := engine.Evaluate(
		"config",
		"instruction.content",
		"ignore previous instructions and ign\u03bfre previous instructions",
	)
	if len(fullSpan) != 2 {
		t.Fatalf("full-span dedup result = %d, want 2: %+v", len(fullSpan), fullSpan)
	}
	if fullSpan[0].Offset != 0 {
		t.Fatalf("first (raw) match offset = %d, want 0", fullSpan[0].Offset)
	}
	if fullSpan[1].Offset == 0 {
		t.Fatalf("appended shadow match should not share raw offset 0: %+v", fullSpan)
	}
}

func TestEngineEvaluateInstructionZeroLengthProjection(t *testing.T) {
	for _, pattern := range []string{`^`, `$`, ``} {
		engine := newCanonicalRuleEngine(t, canonicalRuleFile{
			filename: "zero.yaml",
			id:       "zero-length-rule",
			yaml: canonicalRuleYAML(
				"zero-length-rule",
				"config",
				pattern,
				"has_injection_patterns",
			),
		})
		got := engine.Evaluate(
			"config",
			"instruction.content",
			"\u200bignore previous instructions",
		)
		if len(got) == 0 {
			t.Fatalf("pattern %q produced no matches", pattern)
		}
		rawLen := len("\u200bignore previous instructions")
		switch pattern {
		case `^`:
			if got[0].Offset != 0 {
				t.Fatalf("^ start offset = %d, want 0", got[0].Offset)
			}
		case `$`:
			last := got[len(got)-1]
			if last.Offset != rawLen {
				t.Fatalf("$ EOF offset = %d, want %d", last.Offset, rawLen)
			}
		case ``:
			var haveStart, haveEnd bool
			for _, m := range got {
				if m.Offset == 0 {
					haveStart = true
				}
				if m.Offset == rawLen {
					haveEnd = true
				}
			}
			if !haveStart || !haveEnd {
				t.Fatalf("empty pattern missing start/EOF: %+v", got)
			}
		}
	}

	// Empty view maps 0 for either bias.
	empty := canonicalizeInstruction("")
	assertPoint(t, empty, 0, projectionLeft, 0)
	assertPoint(t, empty, 0, projectionRight, 0)

	// A zero-length point inside ﬃ → ffi uses right bias and maps to the
	// ligature's raw end.
	lig := canonicalizeInstruction("\uFB03")
	assertPoint(t, lig, 1, projectionRight, len("\uFB03"))
	assertPoint(t, lig, 2, projectionRight, len("\uFB03"))
}

func TestEngineEvaluateInstructionOneMiBBoundaries(t *testing.T) {
	engine := canonicalIgnoreEngine(t)
	marker := " ignore previous instructions"

	// Positive phrase wholly inside and ending exactly at byte 1 MiB.
	inside := strings.Repeat("a", maxInputBytes-len(marker)) + marker
	if len(inside) != maxInputBytes {
		t.Fatalf("inside length = %d", len(inside))
	}
	if got := engine.Evaluate("config", "instruction.content", inside); len(got) == 0 {
		t.Fatal("phrase ending at 1 MiB should match")
	}

	// A fullwidth rune straddling the raw cap is truncated to an invalid byte;
	// it must not match or panic.
	crossRune := strings.Repeat("a", maxInputBytes-1) + "Ｉ"
	if got := engine.Evaluate("config", "instruction.content", crossRune); len(got) != 0 {
		t.Fatalf("boundary-crossing rune matched: %+v", got)
	}

	// A phrase straddling the raw cap is cut and must not match.
	crossPhrase := strings.Repeat("a", maxInputBytes-10) + marker
	if got := engine.Evaluate("config", "instruction.content", crossPhrase); len(got) != 0 {
		t.Fatalf("boundary-crossing phrase matched: %+v", got)
	}

	// Canonical cap prevents matching an unrepresented obfuscated suffix.
	obf := "Ｉｇｎｏｒｅ previous instructions"
	if got := engine.Evaluate("config", "instruction.content", obf); len(got) == 0 {
		t.Fatal("small obfuscated phrase should match (positive control)")
	}
	// "\u2167" (Ⅷ) expands to "VIII" under NFKC; a full raw buffer of them fills
	// the canonical output cap so the trailing obfuscated phrase is never
	// represented in the canonical view and cannot match.
	filler := strings.Repeat("\u2167", maxInputBytes/4)
	capped := filler + obf
	if len(capped) > maxInputBytes {
		t.Fatalf("capped input exceeds raw cap: %d", len(capped))
	}
	if got := engine.Evaluate("config", "instruction.content", capped); len(got) != 0 {
		t.Fatalf("unrepresented obfuscated suffix matched: %+v", got)
	}
}

func TestEngineEvaluateInstructionCustomRuleAndRunTestsParity(t *testing.T) {
	obfuscated := "ｉｇｎｏｒｅ\u200b previous instructions"

	// Custom eligible rule matches at runtime and under RunTests.
	eligible := Rule{
		ID:       "custom-eligible-parity",
		Name:     "Custom eligible parity",
		Version:  1,
		Enabled:  true,
		Severity: "high",
		Scope:    Scope{Collector: "config", Targets: []string{"instruction.content"}},
		Matcher: MatcherSpec{
			Type:            "regex",
			Pattern:         `\bignore\s+previous\s+instructions\b`,
			CaseInsensitive: true,
		},
		Emit: EmitConfig{FindingType: "has_injection_patterns"},
		Tests: []TestCase{
			{Input: obfuscated, ShouldMatch: true, Description: "nfkc+zero-width"},
		},
	}
	engine := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "eligible.yaml",
		id:       "custom-eligible-parity",
		yaml: canonicalRuleYAML(
			"custom-eligible-parity",
			"config",
			`\bignore\s+previous\s+instructions\b`,
			"has_injection_patterns",
		),
	})
	if got := engine.Evaluate("config", "instruction.content", obfuscated); len(got) == 0 {
		t.Fatal("custom eligible rule should match obfuscated input at runtime")
	}
	if failures := RunTests(eligible); len(failures) != 0 {
		t.Fatalf("custom eligible RunTests failures: %+v", failures)
	}

	// Custom non-injection rule remains raw-only at runtime and under RunTests.
	nonInjection := Rule{
		ID:       "custom-noninjection-parity",
		Name:     "Custom non-injection parity",
		Version:  1,
		Enabled:  true,
		Severity: "medium",
		Scope:    Scope{Collector: "config", Targets: []string{"instruction.content"}},
		Matcher: MatcherSpec{
			Type:            "regex",
			Pattern:         `\bignore\s+previous\s+instructions\b`,
			CaseInsensitive: true,
		},
		Emit: EmitConfig{FindingType: "has_secret"},
		Tests: []TestCase{
			{Input: obfuscated, ShouldMatch: false, Description: "no canonical for non-injection"},
			{Input: "ignore previous instructions", ShouldMatch: true, Description: "raw still matches"},
		},
	}
	nonInjEngine := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "noninjection.yaml",
		id:       "custom-noninjection-parity",
		yaml: canonicalRuleYAML(
			"custom-noninjection-parity",
			"config",
			`\bignore\s+previous\s+instructions\b`,
			"has_secret",
		),
	})
	if got := nonInjEngine.Evaluate("config", "instruction.content", obfuscated); got != nil {
		t.Fatalf("non-injection rule matched obfuscated input: %+v", got)
	}
	if failures := RunTests(nonInjection); len(failures) != 0 {
		t.Fatalf("custom non-injection RunTests failures: %+v", failures)
	}

	// A multi-target eligible rule receives canonical RunTests semantics.
	multiTarget := Rule{
		ID:       "custom-multitarget-parity",
		Name:     "Custom multi-target parity",
		Version:  1,
		Enabled:  true,
		Severity: "high",
		Scope: Scope{
			Collector: "config",
			Targets:   []string{"tool.description", "instruction.content"},
		},
		Matcher: MatcherSpec{
			Type:            "regex",
			Pattern:         `\bignore\s+previous\s+instructions\b`,
			CaseInsensitive: true,
		},
		Emit: EmitConfig{FindingType: "has_injection_patterns"},
		Tests: []TestCase{
			{Input: obfuscated, ShouldMatch: true, Description: "multi-target canonical"},
		},
	}
	if failures := RunTests(multiTarget); len(failures) != 0 {
		t.Fatalf("multi-target RunTests failures: %+v", failures)
	}
}

func TestEngineEvaluateInstructionHighCardinalityRegexes(t *testing.T) {
	input := strings.Repeat("Ａ\u200B", 4096)
	engine := newCanonicalRuleEngine(t,
		canonicalRuleFile{
			filename: "dot.yaml",
			id:       "high-card-dot",
			yaml: canonicalRuleYAML(
				"high-card-dot",
				"config",
				`.`,
				"has_injection_patterns",
			),
		},
		canonicalRuleFile{
			filename: "empty.yaml",
			id:       "high-card-empty",
			yaml: canonicalRuleYAML(
				"high-card-empty",
				"config",
				``,
				"has_injection_patterns",
			),
		},
	)

	got := engine.Evaluate("config", "instruction.content", input)
	want := expectedRawMatches(engine, "config", "instruction.content", input)
	if len(want) == 0 {
		t.Fatal("expected raw matches for high-cardinality regexes")
	}
	if !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatal("raw cardinality/order not preserved for high-cardinality regexes")
	}

	seen := map[string]bool{}
	for _, m := range got[len(want):] {
		key := fmt.Sprintf("%s:%d:%d", m.RuleID, m.Offset, len(m.Text))
		if seen[key] {
			t.Fatalf("duplicate projected shadow identity: %s", key)
		}
		seen[key] = true
	}
}

func TestEngineEvaluateInstructionConcurrent(t *testing.T) {
	engine := newCanonicalRuleEngine(t, canonicalRuleFile{
		filename: "canonical-ignore.yaml",
		id:       "canonical-ignore-test",
		yaml:     canonicalInjectionRuleYAML,
	})
	input := "prefix Ｉｇｎｏｒｅ\u200B previous instructions suffix"
	want := engine.Evaluate(
		"config",
		"instruction.content",
		input,
	)
	if len(want) == 0 {
		t.Fatal("expected canonical instruction match")
	}

	const workers = 32
	const iterations = 100
	results := make(chan []Match, workers*iterations)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				results <- engine.Evaluate(
					"config",
					"instruction.content",
					input,
				)
			}
		}()
	}
	wg.Wait()
	close(results)

	count := 0
	for got := range results {
		count++
		if !reflect.DeepEqual(got, want) {
			t.Errorf("concurrent result = %+v, want %+v", got, want)
		}
	}
	if count != workers*iterations {
		t.Errorf(
			"received %d results, want %d",
			count,
			workers*iterations,
		)
	}
}

package rules

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func assertPoint(
	t *testing.T,
	view canonicalView,
	offset int,
	bias projectionBias,
	want int,
) {
	t.Helper()
	got, ok := view.projectPoint(offset, bias)
	if !ok || got != want {
		t.Fatalf(
			"projectPoint(%d,%d) = (%d,%v), want (%d,true)",
			offset,
			bias,
			got,
			ok,
			want,
		)
	}
}

func assertRange(
	t *testing.T,
	view canonicalView,
	start int,
	end int,
	wantStart int,
	wantEnd int,
) {
	t.Helper()
	gotStart, gotEnd, ok := view.projectRange(start, end)
	if !ok || gotStart != wantStart || gotEnd != wantEnd {
		t.Fatalf(
			"projectRange(%d,%d) = (%d,%d,%v), want (%d,%d,true)",
			start,
			end,
			gotStart,
			gotEnd,
			ok,
			wantStart,
			wantEnd,
		)
	}
}

func TestCanonicalViewProjectionNFKC(t *testing.T) {
	ligature := canonicalizeInstruction("\uFB03")
	if ligature.text != "ffi" {
		t.Fatalf("ligature = %q", ligature.text)
	}
	assertRange(t, ligature, 0, 1, 0, len("\uFB03"))
	assertRange(t, ligature, 1, 2, 0, len("\uFB03"))
	assertPoint(t, ligature, 1, projectionLeft, 0)
	assertPoint(t, ligature, 1, projectionRight, len("\uFB03"))
	assertPoint(t, ligature, 2, projectionLeft, 0)
	assertPoint(t, ligature, 2, projectionRight, len("\uFB03"))

	combining := canonicalizeInstruction("e\u0301")
	if combining.text != "é" {
		t.Fatalf("combining = %q", combining.text)
	}
	assertRange(t, combining, 0, len("é"), 0, len("e\u0301"))
	assertPoint(t, combining, 1, projectionLeft, 0)
	assertPoint(t, combining, 1, projectionRight, len("e\u0301"))

	empty := canonicalizeInstruction("")
	assertPoint(t, empty, 0, projectionLeft, 0)
	assertPoint(t, empty, 0, projectionRight, 0)
	if _, _, ok := empty.projectRange(-1, 0); ok {
		t.Fatal("negative range accepted")
	}
}

func TestCanonicalViewProjectionZeroAllocations(t *testing.T) {
	view := canonicalizeInstruction(strings.Repeat("Ａ\u200B", 4096))
	allocs := testing.AllocsPerRun(1000, func() {
		_, _, ok := view.projectRange(1, 2)
		if !ok {
			panic("projection failed")
		}
	})
	if allocs != 0 {
		t.Fatalf("projectRange allocations = %v, want 0", allocs)
	}
}

func TestCanonicalizeInstructionNFKC(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"fullwidth", "ｉｇｎｏｒｅ", "ignore"},
		{"ligature", "\uFB03", "ffi"},
		{"combining", "e\u0301", "é"},
		{"expansion", "\u3304", "イニング"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := canonicalizeInstruction(tc.raw)
			if view.text != tc.want {
				t.Fatalf("text = %q, want %q", view.text, tc.want)
			}
			if !view.changed {
				t.Fatalf("changed = false, want true for %q", tc.raw)
			}
			// The full canonical output projects to the full raw input,
			// so evidence covers every contributing source byte.
			assertRange(t, view, 0, len(tc.want), 0, len(tc.raw))
			if view.sourceEnd != len(tc.raw) {
				t.Fatalf("sourceEnd = %d, want %d", view.sourceEnd, len(tc.raw))
			}
		})
	}
}

func TestCanonicalizeInstructionInvalidUTF8Barrier(t *testing.T) {
	raw := string([]byte("ig\xffnore"))
	view := canonicalizeInstruction(raw)
	if view.text != raw {
		t.Fatalf("text = %q, want %q (invalid byte preserved)", view.text, raw)
	}
	// The lone 0xff byte projects to exactly its single raw byte.
	assertRange(t, view, 2, 3, 2, 3)
	assertPoint(t, view, 2, projectionLeft, 2)
	assertPoint(t, view, 3, projectionRight, 3)
	if view.sourceEnd != len(raw) {
		t.Fatalf("sourceEnd = %d, want %d", view.sourceEnd, len(raw))
	}

	// An invalid byte between a base letter and a combining mark terminates
	// normalization context, preventing composition across the barrier.
	barrier := string([]byte("e\xff\u0301"))
	got := canonicalizeInstruction(barrier)
	if got.text != barrier {
		t.Fatalf(
			"composition crossed invalid barrier: text = %q, want %q",
			got.text,
			barrier,
		)
	}
}

func TestCanonicalizeInstructionCaps(t *testing.T) {
	raw := strings.Repeat("\u2167", maxInputBytes/3)
	view := canonicalizeInstruction(raw)
	if len(view.text) != maxInputBytes {
		t.Fatalf("canonical length = %d, want %d", len(view.text), maxInputBytes)
	}
	if !utf8.ValidString(view.text) {
		t.Fatal("canonical output is not valid UTF-8")
	}
	if view.text != strings.Repeat("VIII", maxInputBytes/4) {
		t.Fatal("canonical output is not exactly complete VIII units")
	}
	if view.sourceEnd != 3*(maxInputBytes/4) {
		t.Fatalf("sourceEnd = %d, want %d", view.sourceEnd, 3*(maxInputBytes/4))
	}
}

func spacedLetters(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte(byte('a' + i%26))
	}
	return sb.String()
}

func TestCanonicalizeInstructionASCIIIdentityFastPath(t *testing.T) {
	prose := strings.Repeat("hello world ", maxInputBytes/12+1)[:maxInputBytes]
	identityCases := []struct {
		name string
		raw  string
		want bool
	}{
		{"ascii prose", prose, true},
		{"lf and spaces", "first line\nsecond line here", true},
		{"tab", "a\tb", false},
		{"vertical tab", "a\vb", false},
		{"form feed", "a\fb", false},
		{"carriage return", "a\rb", false},
		{"four letter spacing", "w x y z", false},
		{"three letter spacing", "x y z", true},
		{"sixtyfive letter spacing", spacedLetters(65), true},
		{"non-ascii byte", "café", false},
	}
	for _, tc := range identityCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := asciiInstructionIdentity(tc.raw); got != tc.want {
				t.Fatalf(
					"asciiInstructionIdentity(%q) = %v, want %v",
					tc.raw,
					got,
					tc.want,
				)
			}
		})
	}

	// The fast path yields an unchanged, single-affine-span identity view.
	view := canonicalizeInstruction("plain ascii instructions")
	if view.changed {
		t.Fatal("expected changed == false for ascii identity input")
	}
	if view.text != "plain ascii instructions" {
		t.Fatalf("identity text = %q", view.text)
	}
	if len(view.spans) != 1 ||
		!view.spans[0].affine ||
		view.spans[0].opaque ||
		view.spans[0].shadowStart != 0 ||
		view.spans[0].shadowEnd != len(view.text) ||
		view.spans[0].rawStart != 0 ||
		view.spans[0].rawEnd != len(view.text) {
		t.Fatalf("identity spans = %+v", view.spans)
	}
	if view.sourceEnd != len(view.text) {
		t.Fatalf("identity sourceEnd = %d", view.sourceEnd)
	}

	empty := canonicalizeInstruction("")
	if empty.changed || len(empty.spans) != 0 || empty.text != "" ||
		empty.sourceEnd != 0 {
		t.Fatalf("empty view = %+v", empty)
	}
}

func TestInstructionCanonicalEligibilityPredicates(t *testing.T) {
	if !isInstructionCanonicalRequest("config", "instruction.content") {
		t.Fatal("exact config/instruction.content request should be eligible")
	}
	for _, tc := range []struct{ collector, target string }{
		{"config", "instruction.Content"},
		{"config", "mcp.tool.description"},
		{"mcp", "instruction.content"},
		{"a2a", "instruction.content"},
		{"Config", "instruction.content"},
		{"", ""},
	} {
		if isInstructionCanonicalRequest(tc.collector, tc.target) {
			t.Fatalf(
				"request %q/%q should not be eligible",
				tc.collector,
				tc.target,
			)
		}
	}

	injAll := Rule{
		Scope: Scope{Collector: "all", Targets: []string{"instruction.content"}},
		Emit:  EmitConfig{FindingType: "has_injection_patterns"},
	}
	injConfig := Rule{
		Scope: Scope{
			Collector: "config",
			Targets:   []string{"other", "instruction.content"},
		},
		Emit: EmitConfig{FindingType: "has_injection_patterns"},
	}
	nonInjection := Rule{
		Scope: Scope{Collector: "config", Targets: []string{"instruction.content"}},
		Emit:  EmitConfig{FindingType: "has_secret"},
	}
	wrongCollector := Rule{
		Scope: Scope{Collector: "mcp", Targets: []string{"instruction.content"}},
		Emit:  EmitConfig{FindingType: "has_injection_patterns"},
	}
	wrongTarget := Rule{
		Scope: Scope{
			Collector: "config",
			Targets:   []string{"mcp.tool.description"},
		},
		Emit: EmitConfig{FindingType: "has_injection_patterns"},
	}

	if !ruleUsesInstructionCanonicalization(injAll) ||
		!ruleUsesInstructionCanonicalization(injConfig) {
		t.Fatal("eligible injection rules should use canonicalization")
	}
	for _, r := range []Rule{nonInjection, wrongCollector, wrongTarget} {
		if ruleUsesInstructionCanonicalization(r) {
			t.Fatalf("rule scope %+v should not use canonicalization", r.Scope)
		}
	}

	if hasInstructionCanonicalCandidate(nil) {
		t.Fatal("nil candidates should not be eligible")
	}
	if hasInstructionCanonicalCandidate([]compiledRule{{rule: nonInjection}}) {
		t.Fatal("non-injection candidates should not be eligible")
	}
	if !hasInstructionCanonicalCandidate(
		[]compiledRule{{rule: nonInjection}, {rule: injAll}},
	) {
		t.Fatal("an eligible candidate should be detected")
	}

	// Dormant semantic version substrate consumed by the digest in Task 6.
	if instructionCanonicalizationVersion !=
		"instruction-shadow-v1+unicode-15.0.0" {
		t.Fatalf(
			"canonicalizer version = %q",
			instructionCanonicalizationVersion,
		)
	}
}

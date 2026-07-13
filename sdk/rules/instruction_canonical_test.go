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

func TestCanonicalViewProjectionDeletedBytes(t *testing.T) {
	raw := "\u200Babc\u200Bdef\u200B"
	view := canonicalizeInstruction(raw)
	if view.text != "abcdef" {
		t.Fatalf("text = %q", view.text)
	}
	assertRange(t, view, 0, 3, len("\u200B"), len("\u200Babc"))
	assertRange(
		t,
		view,
		3,
		6,
		len("\u200Babc\u200B"),
		len("\u200Babc\u200Bdef"),
	)
	assertRange(
		t,
		view,
		0,
		6,
		len("\u200B"),
		len("\u200Babc\u200Bdef"),
	)
	assertPoint(t, view, 0, projectionLeft, 0)
	assertPoint(t, view, 0, projectionRight, 0)
	assertPoint(t, view, 3, projectionLeft, len("\u200Babc"))
	assertPoint(
		t,
		view,
		3,
		projectionRight,
		len("\u200Babc\u200B"),
	)
	assertPoint(t, view, 6, projectionLeft, len(raw))
	assertPoint(t, view, 6, projectionRight, len(raw))
}

func TestCanonicalizeInstructionRemovesOnlyEnumeratedControls(t *testing.T) {
	removed := []rune{
		'\u034F', '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF',
		'\u061C', '\u200E', '\u200F',
	}
	addRange := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			removed = append(removed, r)
		}
	}
	addRange('\u202A', '\u202E')
	addRange('\u2066', '\u2069')
	addRange('\U000E0000', '\U000E007F')
	addRange('\uFE00', '\uFE0F')
	addRange('\U000E0100', '\U000E01EF')

	for _, r := range removed {
		raw := "a" + string(r) + "b"
		view := canonicalizeInstruction(raw)
		if view.text != "ab" {
			t.Fatalf("U+%04X not removed: text = %q", r, view.text)
		}
		if !view.changed {
			t.Fatalf("U+%04X removal should set changed", r)
		}
		// The kept letters project back across the deleted rune's raw gap.
		assertRange(t, view, 0, 2, 0, len(raw))
		assertPoint(t, view, 1, projectionLeft, 1)
		assertPoint(t, view, 1, projectionRight, 1+len(string(r)))
	}

	// Runes NOT in the enumerated set are never removed as a class, even when
	// they are format characters (U+00AD) or a formerly-space code point
	// (U+180E).
	for _, r := range []rune{'\u00AD', '\u180E'} {
		raw := "a" + string(r) + "b"
		view := canonicalizeInstruction(raw)
		if view.text != raw {
			t.Fatalf("U+%04X should remain: text = %q", r, view.text)
		}
	}
}

func TestCanonicalizeInstructionMapsWhitespace(t *testing.T) {
	horizontal := []rune{
		'\u0009', '\u0020', '\u00A0', '\u1680',
		'\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005',
		'\u2006', '\u2007', '\u2008', '\u2009', '\u200A',
		'\u202F', '\u205F', '\u3000',
	}
	for _, r := range horizontal {
		raw := "a" + string(r) + "b"
		view := canonicalizeInstruction(raw)
		if view.text != "a b" {
			t.Fatalf("U+%04X horizontal -> %q, want %q", r, view.text, "a b")
		}
	}

	vertical := []rune{
		'\u000A', '\u000B', '\u000C', '\u000D',
		'\u0085', '\u2028', '\u2029',
	}
	for _, r := range vertical {
		raw := "a" + string(r) + "b"
		view := canonicalizeInstruction(raw)
		if view.text != "a\nb" {
			t.Fatalf("U+%04X vertical -> %q, want %q", r, view.text, "a\nb")
		}
	}

	// Adjacent horizontal whitespace is mapped one-for-one; spaces are never
	// collapsed.
	multi := canonicalizeInstruction("a\u2000\u2000b")
	if multi.text != "a  b" {
		t.Fatalf("adjacent spaces collapsed: %q", multi.text)
	}

	// CRLF becomes exactly two newlines; a newline is never mapped to a space.
	crlf := canonicalizeInstruction("a\r\nb")
	if crlf.text != "a\n\nb" {
		t.Fatalf("CRLF -> %q, want %q", crlf.text, "a\n\nb")
	}

	// A mapped multi-byte space projects back to its full contributing raw
	// bytes.
	nbsp := canonicalizeInstruction("a\u00A0b")
	if nbsp.text != "a b" {
		t.Fatalf("NBSP -> %q", nbsp.text)
	}
	assertRange(t, nbsp, 1, 2, 1, 1+len("\u00A0"))
}

func TestCanonicalizeInstructionTagsAndVariationSelectors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"emoji vs16", "ignore\uFE0F", "ignore"},
		{"text vs15", "a\uFE0Eb", "ab"},
		{"supplementary vs", "a\U000E0100b", "ab"},
		{"supplementary vs high", "a\U000E01EFb", "ab"},
		{"tag language", "a\U000E0001b", "ab"},
		{"tag chars", "a\U000E0041\U000E0042b", "ab"},
		{"tag cancel", "a\U000E007Fb", "ab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := canonicalizeInstruction(tc.raw)
			if view.text != tc.want {
				t.Fatalf("text = %q, want %q", view.text, tc.want)
			}
		})
	}
}

func TestCanonicalizeInstructionDeletedBytesBeforeInsideAfter(t *testing.T) {
	zw := "\u200B"
	raw := zw + "ig" + zw + "nore" + zw
	view := canonicalizeInstruction(raw)
	if view.text != "ignore" {
		t.Fatalf("text = %q", view.text)
	}
	// The whole canonical phrase excludes the deleted-before and deleted-after
	// bytes but bridges the deleted-inside bytes.
	assertRange(
		t,
		view,
		0,
		len("ignore"),
		len(zw),
		len(zw+"ig"+zw+"nore"),
	)
	// A sub-match ending before the interior deletion.
	assertRange(t, view, 0, len("ig"), len(zw), len(zw+"ig"))
	// A sub-match starting after the interior deletion.
	assertRange(
		t,
		view,
		len("ig"),
		len("ignore"),
		len(zw+"ig"+zw),
		len(zw+"ig"+zw+"nore"),
	)
	// Boundary bias straddling the interior deletion.
	assertPoint(t, view, len("ig"), projectionLeft, len(zw+"ig"))
	assertPoint(t, view, len("ig"), projectionRight, len(zw+"ig"+zw))
	// Canonical start/EOF ignore the deleted prefix/suffix.
	assertPoint(t, view, 0, projectionRight, 0)
	assertPoint(t, view, len("ignore"), projectionLeft, len(raw))
}

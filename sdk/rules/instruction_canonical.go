package rules

import (
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// instructionCanonicalizationVersion identifies the frozen V1 canonical shadow
// transform contract together with the Unicode edition of the normalization
// tables it depends on. It is dormant until the semantic digest consumes it.
const instructionCanonicalizationVersion = "instruction-shadow-v1+unicode-" + norm.Version

// projectionBias selects which raw boundary a non-affine or between-span offset
// projects to.
type projectionBias uint8

const (
	projectionLeft projectionBias = iota
	projectionRight
)

// sourceSpan maps a contiguous, non-empty shadow byte range back onto the raw
// input byte range that produced it.
type sourceSpan struct {
	shadowStart int
	shadowEnd   int
	rawStart    int
	rawEnd      int
	affine      bool
	opaque      bool
}

// canonicalView is the bounded canonical shadow of a raw instruction string
// plus the ordered, coalesced provenance spans required to project shadow
// offsets back to raw byte offsets.
type canonicalView struct {
	text      string
	spans     []sourceSpan
	sourceEnd int
	changed   bool
}

// projectPoint maps a shadow byte offset back to a raw byte offset in
// O(log S) with zero allocations.
func (v canonicalView) projectPoint(
	offset int,
	bias projectionBias,
) (int, bool) {
	if offset < 0 || offset > len(v.text) {
		return 0, false
	}
	if len(v.text) == 0 {
		return 0, offset == 0
	}
	if offset == 0 {
		return 0, true
	}
	if offset == len(v.text) {
		return v.sourceEnd, true
	}

	i := sort.Search(len(v.spans), func(i int) bool {
		return v.spans[i].shadowEnd >= offset
	})
	if i == len(v.spans) {
		return 0, false
	}
	span := v.spans[i]
	if offset > span.shadowStart && offset < span.shadowEnd {
		if span.affine {
			return span.rawStart + offset - span.shadowStart, true
		}
		if bias == projectionLeft {
			return span.rawStart, true
		}
		return span.rawEnd, true
	}
	if bias == projectionLeft {
		return span.rawEnd, true
	}
	if i+1 < len(v.spans) && v.spans[i+1].shadowStart == offset {
		return v.spans[i+1].rawStart, true
	}
	return span.rawEnd, true
}

// projectRange maps a shadow byte range back to the raw byte range covering
// every contributing source byte in O(log S) with zero allocations.
func (v canonicalView) projectRange(
	start int,
	end int,
) (int, int, bool) {
	if start < 0 || end < start || end > len(v.text) {
		return 0, 0, false
	}
	if start == end {
		point, ok := v.projectPoint(start, projectionRight)
		return point, point, ok
	}

	first := sort.Search(len(v.spans), func(i int) bool {
		return v.spans[i].shadowEnd > start
	})
	afterLast := sort.Search(len(v.spans), func(i int) bool {
		return v.spans[i].shadowStart >= end
	})
	if first == len(v.spans) || afterLast == 0 || first >= afterLast {
		return 0, 0, false
	}
	firstSpan := v.spans[first]
	lastSpan := v.spans[afterLast-1]

	rawStart := firstSpan.rawStart
	if firstSpan.affine {
		rawStart += start - firstSpan.shadowStart
	}
	rawEnd := lastSpan.rawEnd
	if lastSpan.affine {
		rawEnd = lastSpan.rawStart + end - lastSpan.shadowStart
	}
	return rawStart, rawEnd, true
}

// canonicalBuilder accumulates canonical output bytes and their provenance
// spans while honoring the canonical 1 MiB output cap.
type canonicalBuilder struct {
	text      []byte
	spans     []sourceSpan
	sourceEnd int
}

// truncateRuleInput enforces the raw 1 MiB input cap on a byte boundary.
func truncateRuleInput(text string) string {
	if len(text) > maxInputBytes {
		return text[:maxInputBytes]
	}
	return text
}

// appendSegment records one atomic canonical segment produced from the raw
// range [rawStart,rawEnd). It never splits a transformed unit across the
// canonical cap: if the whole segment would exceed maxInputBytes it is left
// unrepresented, sourceEnd is set to the segment's rawStart, and false is
// returned so the caller stops all further processing.
func (b *canonicalBuilder) appendSegment(
	out []byte,
	rawStart int,
	rawEnd int,
	affine bool,
	opaque bool,
) bool {
	if len(b.text)+len(out) > maxInputBytes {
		b.sourceEnd = rawStart
		return false
	}
	if len(out) == 0 {
		// Deleted / zero-output segment: consume the raw bytes and advance
		// sourceEnd, but emit no span.
		b.sourceEnd = rawEnd
		return true
	}
	shadowStart := len(b.text)
	b.text = append(b.text, out...)
	shadowEnd := len(b.text)
	b.sourceEnd = rawEnd

	// Coalesce with the previous span only when the mapping stays byte-affine,
	// raw-contiguous, shadow-contiguous, and neither span is opaque.
	if n := len(b.spans); n > 0 {
		prev := &b.spans[n-1]
		if prev.affine && affine && !prev.opaque && !opaque &&
			prev.rawEnd == rawStart && prev.shadowEnd == shadowStart {
			prev.shadowEnd = shadowEnd
			prev.rawEnd = rawEnd
			return true
		}
	}
	b.spans = append(b.spans, sourceSpan{
		shadowStart: shadowStart,
		shadowEnd:   shadowEnd,
		rawStart:    rawStart,
		rawEnd:      rawEnd,
		affine:      affine,
		opaque:      opaque,
	})
	return true
}

func (b canonicalBuilder) view() canonicalView {
	return canonicalView{
		text:      string(b.text),
		spans:     b.spans,
		sourceEnd: b.sourceEnd,
	}
}

// canonicalizeNFKC applies NFKC normalization while preserving provenance. It
// splits the raw input into maximal valid UTF-8 runs; each invalid byte is an
// opaque affine barrier that terminates normalization context (so composition
// cannot cross it), and every NFKC output segment maps to the exact source
// bytes the normalizer consumed for it.
func canonicalizeNFKC(raw string) canonicalView {
	var b canonicalBuilder
	i := 0
	for i < len(raw) {
		r, size := utf8.DecodeRuneInString(raw[i:])
		if r == utf8.RuneError && size == 1 {
			if !b.appendSegment([]byte(raw[i:i+1]), i, i+1, true, true) {
				return b.view()
			}
			i++
			continue
		}

		runStart := i
		j := i + size
		for j < len(raw) {
			r2, size2 := utf8.DecodeRuneInString(raw[j:])
			if r2 == utf8.RuneError && size2 == 1 {
				break
			}
			j += size2
		}

		run := raw[runStart:j]
		var it norm.Iter
		it.InitString(norm.NFKC, run)
		// norm.Iter can emit a single source unit's decomposition across
		// several Next() calls whose Pos() only advances on the final
		// sub-output (e.g. U+FB03 -> "f","f","i" all mapping to one source
		// rune). Accumulate consecutive outputs that share a source range and
		// emit one span per contributing source range, so one-to-many maps map
		// the whole output back to every contributing source byte.
		segStart := it.Pos()
		var pending []byte
		for !it.Done() {
			before := it.Pos()
			out := it.Next()
			after := it.Pos()
			pending = append(pending, out...)
			if after <= before {
				continue
			}
			rawStart := runStart + segStart
			rawEnd := runStart + after
			affine := string(pending) == raw[rawStart:rawEnd]
			if !b.appendSegment(pending, rawStart, rawEnd, affine, false) {
				return b.view()
			}
			pending = pending[:0]
			segStart = after
		}
		i = j
	}
	return b.view()
}

// asciiInstructionLetter reports whether b is an ASCII Latin letter.
func asciiInstructionLetter(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

// asciiInstructionIdentity reports whether raw is already byte-identical to its
// canonical shadow: pure ASCII, with only ASCII space and newline whitespace,
// and no genuinely collapsible 4–64 letter-spacing run. When true, the second
// matcher pass can be skipped entirely.
func asciiInstructionIdentity(raw string) bool {
	for i := 0; i < len(raw); {
		b := raw[i]
		if b >= utf8.RuneSelf {
			return false
		}
		switch b {
		case '\t', '\v', '\f', '\r':
			return false
		}
		if !asciiInstructionLetter(b) {
			i++
			continue
		}

		letters := 1
		end := i
		for end+2 < len(raw) &&
			raw[end+1] == ' ' &&
			asciiInstructionLetter(raw[end+2]) {
			letters++
			end += 2
		}
		if letters >= 4 && letters <= 64 {
			return false
		}
		if end > i {
			i = end + 1
			continue
		}
		i++
	}
	return true
}

// identityCanonicalView returns the canonical view for raw when raw is already
// byte-identical to its shadow. Empty input yields an empty view with no spans.
func identityCanonicalView(raw string) canonicalView {
	if raw == "" {
		return canonicalView{}
	}
	return canonicalView{
		text: raw,
		spans: []sourceSpan{{
			shadowStart: 0,
			shadowEnd:   len(raw),
			rawStart:    0,
			rawEnd:      len(raw),
			affine:      true,
		}},
		sourceEnd: len(raw),
		changed:   false,
	}
}

// removeInstructionRune reports whether r is one of the exact, enumerated
// invisible/control code points removed after NFKC. Only these specific
// singletons and ranges are removed; U+00AD, U+180E, arbitrary Cf, punctuation,
// and combining marks are never removed as a class.
func removeInstructionRune(r rune) bool {
	switch r {
	case '\u034F', '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF',
		'\u061C', '\u200E', '\u200F':
		return true
	}
	return r >= '\u202A' && r <= '\u202E' ||
		r >= '\u2066' && r <= '\u2069' ||
		r >= '\U000E0000' && r <= '\U000E007F' ||
		r >= '\uFE00' && r <= '\uFE0F' ||
		r >= '\U000E0100' && r <= '\U000E01EF'
}

// instructionWhitespace maps each enumerated horizontal whitespace code point
// to a single ASCII space and each enumerated vertical whitespace code point to
// a single ASCII newline. Multiplicity is preserved (adjacent spaces are not
// collapsed) and vertical code points are never converted to spaces. The bool
// result reports whether r was mapped.
func instructionWhitespace(r rune) (rune, bool) {
	switch {
	case r == '\t', r == ' ', r == '\u00A0', r == '\u1680',
		r >= '\u2000' && r <= '\u200A',
		r == '\u202F', r == '\u205F', r == '\u3000':
		return ' ', true
	case r == '\n', r == '\v', r == '\f', r == '\r',
		r == '\u0085', r == '\u2028', r == '\u2029':
		return '\n', true
	default:
		return r, false
	}
}

// canonicalizeControlsAndWhitespace applies the frozen V1 enumerated removal
// and whitespace mapping to an NFKC view while preserving provenance. It walks
// the input spans in monotonically increasing shadow order with a forward
// cursor (O(S+N), never a per-match linear scan):
//
//   - Opaque (invalid-byte) spans are copied unchanged and reset context.
//   - Affine spans map raw bytes 1:1, so they are rewritten rune-by-rune:
//     removed runes emit no span (opening a raw gap), a single-byte whitespace
//     map that preserves the byte stays affine, and other maps retain the
//     rune's exact raw bounds.
//   - Non-affine spans are indivisible NFKC decompositions, so the transform is
//     applied to the whole span and any surviving output maps back to its full
//     contributing raw range.
func canonicalizeControlsAndWhitespace(view canonicalView) canonicalView {
	var b canonicalBuilder
	var scratch []byte
	for _, span := range view.spans {
		if span.opaque {
			if !b.appendSegment(
				[]byte(view.text[span.shadowStart:span.shadowEnd]),
				span.rawStart,
				span.rawEnd,
				span.affine,
				true,
			) {
				return b.view()
			}
			continue
		}
		seg := view.text[span.shadowStart:span.shadowEnd]
		if !span.affine {
			scratch = scratch[:0]
			for i := 0; i < len(seg); {
				r, size := utf8.DecodeRuneInString(seg[i:])
				if !removeInstructionRune(r) {
					if mapped, ok := instructionWhitespace(r); ok {
						scratch = append(scratch, byte(mapped))
					} else {
						scratch = append(scratch, seg[i:i+size]...)
					}
				}
				i += size
			}
			if !b.appendSegment(scratch, span.rawStart, span.rawEnd, false, false) {
				return b.view()
			}
			continue
		}
		// Affine span: batch consecutive kept runes into one affine segment and
		// flush on each removed or mapped rune so raw gaps and maps keep exact
		// bounds.
		keepStart := 0
		for i := 0; i < len(seg); {
			r, size := utf8.DecodeRuneInString(seg[i:])
			mapped, isWS := instructionWhitespace(r)
			if !removeInstructionRune(r) && !isWS {
				i += size
				continue
			}
			if i > keepStart {
				if !b.appendSegment(
					[]byte(seg[keepStart:i]),
					span.rawStart+keepStart,
					span.rawStart+i,
					true,
					false,
				) {
					return b.view()
				}
			}
			rawStart := span.rawStart + i
			rawEnd := rawStart + size
			if isWS {
				if !b.appendSegment(
					[]byte{byte(mapped)},
					rawStart,
					rawEnd,
					r == mapped,
					false,
				) {
					return b.view()
				}
			} else if !b.appendSegment(nil, rawStart, rawEnd, false, false) {
				return b.view()
			}
			i += size
			keepStart = i
		}
		if len(seg) > keepStart {
			if !b.appendSegment(
				[]byte(seg[keepStart:]),
				span.rawStart+keepStart,
				span.rawStart+len(seg),
				true,
				false,
			) {
				return b.view()
			}
		}
	}
	return b.view()
}

// canonicalizeInstruction builds the bounded canonical shadow of raw. It caps
// the raw input, takes the ASCII identity fast path when possible, and
// otherwise runs the V1 transform pipeline: NFKC, then enumerated control
// removal and whitespace mapping.
func canonicalizeInstruction(raw string) canonicalView {
	raw = truncateRuleInput(raw)
	if asciiInstructionIdentity(raw) {
		return identityCanonicalView(raw)
	}
	view := canonicalizeNFKC(raw)
	view = canonicalizeControlsAndWhitespace(view)
	view.changed = view.text != raw
	return view
}

// isInstructionCanonicalRequest reports whether a request targets the exact
// config instruction content field eligible for the canonical shadow pass.
func isInstructionCanonicalRequest(collector, target string) bool {
	return collector == "config" && target == "instruction.content"
}

// ruleUsesInstructionCanonicalization reports whether a rule can participate in
// config instruction canonicalization: it emits the injection finding type and
// its scope resolves the config instruction content field.
func ruleUsesInstructionCanonicalization(rule Rule) bool {
	if rule.Emit.FindingType != "has_injection_patterns" {
		return false
	}
	if rule.Scope.Collector != "config" && rule.Scope.Collector != "all" {
		return false
	}
	for _, target := range rule.Scope.Targets {
		if target == "instruction.content" {
			return true
		}
	}
	return false
}

// hasInstructionCanonicalCandidate reports whether any already scope-resolved
// candidate emits the injection finding type. Candidates reaching this check
// are only produced for an eligible request, so the finding-type gate mirrors
// the per-rule shadow gate exactly.
func hasInstructionCanonicalCandidate(candidates []compiledRule) bool {
	for _, cr := range candidates {
		if cr.rule.Emit.FindingType == "has_injection_patterns" {
			return true
		}
	}
	return false
}

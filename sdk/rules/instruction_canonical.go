package rules

import (
	"sort"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// instructionCanonicalizationVersion identifies the frozen V1 canonical shadow
// transform contract together with the Unicode edition of the normalization
// tables it depends on. It is dormant until the semantic digest consumes it.
const instructionCanonicalizationVersion = "instruction-shadow-v1+unicode-" + norm.Version

// maxCanonicalSpans bounds the provenance spans one canonical builder may hold.
// Byte-preserving transforms coalesce, so normal text stays far below this;
// only adversarial inputs that force one non-affine span per rune (e.g. a
// megabyte of NBSP or distinct decomposing runes) approach it. On breach the
// builder declines (overflow) and the caller skips the shadow, capping
// worst-case provenance memory at ~10 MiB/stage (maxCanonicalSpans * 40 B).
const maxCanonicalSpans = maxInputBytes / 4

// spanCap bounds a preallocation hint to the provenance ceiling so a large
// input cannot reserve an unbounded span slice up front.
func spanCap(n int) int {
	if n > maxCanonicalSpans {
		return maxCanonicalSpans
	}
	return n
}

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
	overflow  bool
	truncated bool
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
	overflow  bool
	truncated bool
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
		b.truncated = true
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
	// Provenance ceiling: a new, non-coalescable span beyond the bound means the
	// input is adversarially non-affine. Decline rather than explode memory; the
	// caller drops the shadow for this input and the raw pass still runs.
	if len(b.spans) >= maxCanonicalSpans {
		b.overflow = true
		return false
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
		overflow:  b.overflow,
		truncated: b.truncated,
	}
}

// canonicalizeNFKC applies NFKC normalization while preserving provenance. It
// splits the raw input into maximal valid UTF-8 runs; each invalid byte is an
// opaque affine barrier that terminates normalization context (so composition
// cannot cross it), and every NFKC output segment maps to the exact source
// bytes the normalizer consumed for it.
func canonicalizeNFKC(raw string) canonicalView {
	// Preallocate to absorb geometric slice regrowth. The /3 span heuristic
	// self-caps for coalescing inputs and needs no rune prescan; RuneCount
	// would over-reserve and can itself breach the 32 MiB ceiling on the
	// pathological single-fullwidth + 1 MiB ASCII input.
	b := canonicalBuilder{
		text:  make([]byte, 0, len(raw)),
		spans: make([]sourceSpan, 0, spanCap(len(raw)/3)),
	}
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
		// A multi-letter word cannot start a collapsible spaced run. Skip the
		// whole word so neither of its boundary letters is counted as an
		// isolated token adjacent to a real run.
		if i+1 < len(raw) && asciiInstructionLetter(raw[i+1]) {
			i += 2
			for i < len(raw) && asciiInstructionLetter(raw[i]) {
				i++
			}
			continue
		}

		letters := 1
		end := i
		for end+2 < len(raw) &&
			raw[end+1] == ' ' &&
			asciiInstructionLetter(raw[end+2]) &&
			(end+3 >= len(raw) || !asciiInstructionLetter(raw[end+3])) {
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
	b := canonicalBuilder{
		text:  make([]byte, 0, len(view.text)),
		spans: make([]sourceSpan, 0, len(view.spans)),
	}
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
				// A 1-byte source whitespace rune maps to a 1-byte space/newline,
				// so the mapping is offset-preserving (affine) even when the byte
				// value changes (e.g. tab -> space). This lets long control runs
				// coalesce with adjacent identity spans with no projection-precision
				// loss. Multi-byte whitespace (NBSP, U+2028, ...) is not
				// offset-preserving and stays non-affine.
				if !b.appendSegment(
					[]byte{byte(mapped)},
					rawStart,
					rawEnd,
					size == 1,
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

// instructionConfusables is the exact frozen V1 map of single-letter Greek and
// Cyrillic confusables to their ASCII Latin fold targets. Only these runes are
// ever folded, and only inside a mixed Latin/confusable word. The keys are
// written as explicit code points because their glyphs are indistinguishable
// from the ASCII targets. A zero target byte means "not mapped".
var instructionConfusables = map[rune]byte{
	// Greek uppercase.
	'\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
	'\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
	'\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
	// Greek lowercase.
	'\u03B9': 'i', '\u03BF': 'o', '\u03C1': 'p', '\u03C7': 'x',
	// Cyrillic uppercase.
	'\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M',
	'\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
	'\u0423': 'Y', '\u0425': 'X', '\u0406': 'I', '\u0408': 'J',
	// Cyrillic lowercase.
	'\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
	'\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
}

// asciiLatinRune reports whether r is an ASCII Latin letter.
func asciiLatinRune(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}

// nextRuneIsLetter reports whether the rune beginning at byte offset off in text
// is a Unicode letter. An offset at or past the end of text is not a letter.
func nextRuneIsLetter(text string, off int) bool {
	if off >= len(text) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(text[off:])
	return unicode.IsLetter(r)
}

// foldInstructionConfusables folds the exact restricted set of Greek/Cyrillic
// confusables to ASCII inside mixed Latin words. It scans maximal Unicode-letter
// runs once (Pass 1) and folds a run only when it holds at least one ASCII Latin
// letter, at least one explicitly mapped confusable, and no other rune;
// multiple explicit folds in one word are allowed. Pure Greek/Cyrillic,
// accented/other-script letters, and unmapped runes are left unchanged.
//
// Pass 2 rebuilds the view once with a forward span cursor (O(S+N)). A mapped
// confusable in an affine span folds to one ASCII byte mapped back to the
// confusable rune's exact raw bytes. NFKC can also produce a mapped confusable
// in a non-affine span; that span is rewritten atomically so the output retains
// the whole source unit as its provenance. Opaque spans are copied verbatim.
func foldInstructionConfusables(view canonicalView) canonicalView {
	text := view.text
	type runRange struct{ start, end int }
	var eligible []runRange
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsLetter(r) {
			i += size
			continue
		}
		start := i
		hasASCII := false
		hasConfusable := false
		onlyMapped := true
		j := i
		for j < len(text) {
			rr, sz := utf8.DecodeRuneInString(text[j:])
			if !unicode.IsLetter(rr) {
				break
			}
			switch {
			case asciiLatinRune(rr):
				hasASCII = true
			case instructionConfusables[rr] != 0:
				hasConfusable = true
			default:
				onlyMapped = false
			}
			j += sz
		}
		if hasASCII && hasConfusable && onlyMapped {
			eligible = append(eligible, runRange{start: start, end: j})
		}
		i = j
	}
	if len(eligible) == 0 {
		return view
	}

	b := canonicalBuilder{
		text:  make([]byte, 0, len(view.text)),
		spans: make([]sourceSpan, 0, len(view.spans)),
	}
	ri := 0
	for _, span := range view.spans {
		if span.opaque {
			if !b.appendSegment(
				[]byte(text[span.shadowStart:span.shadowEnd]),
				span.rawStart,
				span.rawEnd,
				span.affine,
				span.opaque,
			) {
				return b.view()
			}
			continue
		}
		if !span.affine {
			keepStart := span.shadowStart
			var replacement []byte
			for o := span.shadowStart; o < span.shadowEnd; {
				r, size := utf8.DecodeRuneInString(text[o:])
				for ri < len(eligible) && eligible[ri].end <= o {
					ri++
				}
				inRun := ri < len(eligible) &&
					o >= eligible[ri].start && o < eligible[ri].end
				if target := instructionConfusables[r]; inRun && target != 0 {
					if replacement == nil {
						replacement = make([]byte, 0, span.shadowEnd-span.shadowStart)
					}
					replacement = append(replacement, text[keepStart:o]...)
					replacement = append(replacement, target)
					keepStart = o + size
				}
				o += size
			}
			if replacement == nil {
				replacement = []byte(text[span.shadowStart:span.shadowEnd])
			} else {
				replacement = append(replacement, text[keepStart:span.shadowEnd]...)
			}
			if !b.appendSegment(
				replacement,
				span.rawStart,
				span.rawEnd,
				false,
				false,
			) {
				return b.view()
			}
			continue
		}
		keepStart := span.shadowStart
		for o := span.shadowStart; o < span.shadowEnd; {
			r, size := utf8.DecodeRuneInString(text[o:])
			for ri < len(eligible) && eligible[ri].end <= o {
				ri++
			}
			inRun := ri < len(eligible) &&
				o >= eligible[ri].start && o < eligible[ri].end
			target := instructionConfusables[r]
			if inRun && target != 0 {
				if o > keepStart {
					if !b.appendSegment(
						[]byte(text[keepStart:o]),
						span.rawStart+keepStart-span.shadowStart,
						span.rawStart+o-span.shadowStart,
						true,
						false,
					) {
						return b.view()
					}
				}
				rawStart := span.rawStart + o - span.shadowStart
				if !b.appendSegment(
					[]byte{target},
					rawStart,
					rawStart+size,
					false,
					false,
				) {
					return b.view()
				}
				o += size
				keepStart = o
				continue
			}
			o += size
		}
		if span.shadowEnd > keepStart {
			if !b.appendSegment(
				[]byte(text[keepStart:span.shadowEnd]),
				span.rawStart+keepStart-span.shadowStart,
				span.rawEnd,
				true,
				false,
			) {
				return b.view()
			}
		}
	}
	return b.view()
}

// collapseInstructionLetterSpacing collapses bounded letter-spacing obfuscation.
// A candidate is a maximal sequence of single ASCII letters separated by exactly
// one canonical ASCII space; only candidates of 4..64 letters are collapsed.
// Runs of 1..3 and 65+ are left wholly unchanged, and two spaces, a newline,
// punctuation, a digit, a non-ASCII letter, or invalid UTF-8 terminate a run.
// Because the whole maximal run is scanned before any decision, a run that
// contains a non-ASCII letter (e.g. an un-folded isolated Cyrillic rune) is
// never collapsed, so "\u0456 g n o r e" stays unchanged.
//
// Pass 1 records the separator-space offsets to delete; Pass 2 rebuilds the view
// once with a forward span cursor (O(S+N)), deleting only those separator spaces
// so the removed spaces become raw gaps that projection bridges back to the
// original spaced slice.
func collapseInstructionLetterSpacing(view canonicalView) canonicalView {
	text := view.text
	var deletes []int
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsLetter(r) {
			i += size
			continue
		}
		// Only an isolated single-letter token can begin or extend a spaced run.
		// Letter tokens are maximal, so the token at i is preceded by a non-letter
		// (or the string start); it is a single letter iff the following rune is
		// not a letter. Landing on a multi-letter word must never start a run, so
		// skip the whole word — this stops the run from absorbing a neighbouring
		// word's boundary letter (e.g. the "p" of "previous").
		if nextRuneIsLetter(text, i+size) {
			i += size
			for i < len(text) {
				rr, sz := utf8.DecodeRuneInString(text[i:])
				if !unicode.IsLetter(rr) {
					break
				}
				i += sz
			}
			continue
		}
		letters := 1
		allASCII := asciiLatinRune(r)
		mark := len(deletes)
		j := i + size
		for j+1 < len(text) && text[j] == ' ' {
			r2, sz2 := utf8.DecodeRuneInString(text[j+1:])
			// A run member must itself be an isolated single letter: a letter
			// immediately followed by another letter is the head of a multi-letter
			// word and terminates the run without joining it.
			if !unicode.IsLetter(r2) || nextRuneIsLetter(text, j+1+sz2) {
				break
			}
			deletes = append(deletes, j)
			letters++
			if !asciiLatinRune(r2) {
				allASCII = false
			}
			j += 1 + sz2
		}
		if !allASCII || letters < 4 || letters > 64 {
			deletes = deletes[:mark]
		}
		i = j
	}
	if len(deletes) == 0 {
		return view
	}

	b := canonicalBuilder{
		text:  make([]byte, 0, len(view.text)),
		spans: make([]sourceSpan, 0, len(view.spans)),
	}
	di := 0
	for _, span := range view.spans {
		if span.opaque {
			if !b.appendSegment(
				[]byte(text[span.shadowStart:span.shadowEnd]),
				span.rawStart,
				span.rawEnd,
				span.affine,
				true,
			) {
				return b.view()
			}
			continue
		}
		if !span.affine {
			for di < len(deletes) && deletes[di] < span.shadowStart {
				di++
			}
			if di < len(deletes) && deletes[di] == span.shadowStart &&
				span.shadowEnd-span.shadowStart == 1 {
				if !b.appendSegment(nil, span.rawStart, span.rawEnd, false, false) {
					return b.view()
				}
				di++
			} else if !b.appendSegment(
				[]byte(text[span.shadowStart:span.shadowEnd]),
				span.rawStart,
				span.rawEnd,
				false,
				false,
			) {
				return b.view()
			}
			continue
		}
		keepStart := span.shadowStart
		for o := span.shadowStart; o < span.shadowEnd; {
			_, size := utf8.DecodeRuneInString(text[o:])
			for di < len(deletes) && deletes[di] < o {
				di++
			}
			if di < len(deletes) && deletes[di] == o {
				if o > keepStart {
					if !b.appendSegment(
						[]byte(text[keepStart:o]),
						span.rawStart+keepStart-span.shadowStart,
						span.rawStart+o-span.shadowStart,
						true,
						false,
					) {
						return b.view()
					}
				}
				rawStart := span.rawStart + o - span.shadowStart
				if !b.appendSegment(nil, rawStart, rawStart+size, false, false) {
					return b.view()
				}
				o += size
				keepStart = o
				di++
				continue
			}
			o += size
		}
		if span.shadowEnd > keepStart {
			if !b.appendSegment(
				[]byte(text[keepStart:span.shadowEnd]),
				span.rawStart+keepStart-span.shadowStart,
				span.rawEnd,
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
// the raw input, takes the ASCII identity fast path when possible, and otherwise
// runs the frozen V1 transform pipeline exactly once with no recursion: NFKC,
// enumerated control removal and whitespace mapping, restricted mixed-script
// confusable folding, then bounded letter-spacing collapse.
func canonicalizeInstruction(raw string) canonicalView {
	raw = truncateRuleInput(raw)
	if asciiInstructionIdentity(raw) {
		return identityCanonicalView(raw)
	}
	view := canonicalizeNFKC(raw)
	if view.overflow {
		return canonicalView{overflow: true}
	}
	truncated := view.truncated
	view = canonicalizeControlsAndWhitespace(view)
	if view.overflow {
		return canonicalView{overflow: true}
	}
	truncated = truncated || view.truncated
	view = foldInstructionConfusables(view)
	if view.overflow {
		return canonicalView{overflow: true}
	}
	truncated = truncated || view.truncated
	view = collapseInstructionLetterSpacing(view)
	if view.overflow {
		return canonicalView{overflow: true}
	}
	truncated = truncated || view.truncated
	view.truncated = truncated
	view.changed = view.text != raw
	return view
}

// isInstructionCanonicalRequest reports whether a request targets the exact
// config instruction content field eligible for the canonical shadow pass.
func isInstructionCanonicalRequest(collector, target string) bool {
	return collector == "config" && target == "instruction.content"
}

// ruleUsesInstructionCanonicalization reports whether a rule can participate in
// config instruction canonicalization: it is not shadow-excluded, emits the
// injection finding type, and its scope resolves the config instruction content
// field. This mirrors the engine's shadow gate so the digest and RunTests treat
// a shadow-excluded rule as canonicalizer-independent.
func ruleUsesInstructionCanonicalization(rule Rule) bool {
	if rule.ShadowExclude {
		return false
	}
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
// candidate participates in the canonical shadow. Candidates reaching this
// check are only produced for an eligible request; the shared rule predicate
// keeps shadow exclusion, digesting, tests, and engine evaluation aligned.
func hasInstructionCanonicalCandidate(candidates []compiledRule) bool {
	for _, cr := range candidates {
		if ruleUsesInstructionCanonicalization(cr.rule) {
			return true
		}
	}
	return false
}

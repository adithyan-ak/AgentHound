package config

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	sharedinstruction "github.com/adithyan-ak/agenthound/sdk/instruction"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const (
	maxDecodedInstructionBytes = 2 << 10
	maxBase64InstructionBytes  = 2732
	maxHexInstructionBytes     = 4096
	maxPercentInstructionBytes = 6144
)

var (
	base64InstructionToken     = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	hexInstructionToken        = regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`)
	percentInstructionToken    = regexp.MustCompile(`[A-Za-z0-9._~%:/-]{32,}`)
	hexDecodeActivationPattern = regexp.MustCompile(
		`(?i)(?:\b(?:hex|hexadecimal)(?:\s*[- ]\s*)?decode\b.{0,96}\b(?:execute|follow|obey|apply|run|treat)\b|\bdecode\b.{0,48}\b(?:hex|hexadecimal|bytes?|payload|content|string)\b.{0,96}\b(?:execute|follow|obey|apply|run|treat)\b)`,
	)
	percentDecodeActivationPattern = regexp.MustCompile(
		`(?i)(?:\b(?:url|percent)(?:\s*[- ]\s*)?decode\b.{0,96}\b(?:execute|follow|obey|apply|run|treat)\b|\bdecode\b.{0,48}\b(?:percent|url|bytes?|payload|content|string)\b.{0,96}\b(?:execute|follow|obey|apply|run|treat)\b)`,
	)
)

type instructionClassification struct {
	verdict      sharedinstruction.Verdict
	signals      []sharedinstruction.Signal
	totalSignals int
}

type candidateSpecificity uint8

const (
	candidateSpecificitySemantic candidateSpecificity = iota
	candidateSpecificityExact
	candidateSpecificityFallback
)

type instructionCandidate struct {
	match          rules.Match
	kind           instructionSemanticKind
	label          string
	strength       sharedinstruction.Strength
	specificity    candidateSpecificity
	decodedExcerpt string
	// offset/length cover the complete semantic token or trigger and are used
	// for layout, correlation, and deduplication.
	offset int
	length int
	// evidenceOffset/evidenceLength identify the exact bounded raw slice exposed
	// through the public evidence contract.
	evidenceOffset int
	evidenceLength int
}

func classifyInstruction(ctx context.Context, data []byte, engine *rules.Engine, allowDecoding bool) (instructionClassification, error) {
	if engine == nil {
		return cleanInstructionClassification(), nil
	}
	if err := ctx.Err(); err != nil {
		return instructionClassification{}, err
	}
	raw := string(data)
	layout := buildInstructionLayout(raw)
	matches, err := engine.EvaluateAllContext(ctx, "config", map[string]string{"instruction.content": raw})
	if err != nil {
		return instructionClassification{}, err
	}
	candidates, err := semanticInstructionCandidates(ctx, raw, layout)
	if err != nil {
		return instructionClassification{}, err
	}

	for index, match := range matches {
		if index%256 == 0 {
			if err := ctx.Err(); err != nil {
				return instructionClassification{}, err
			}
		}
		if match.Emit.FindingType != "has_injection_patterns" {
			continue
		}
		label := match.RuleID
		if len(match.Labels) > 0 {
			label = match.Labels[0]
		}
		switch label {
		case "always_use", "never_use_other", "instead_of", "curl_wget", "embedded_url", "exfil_url", "base64_instruction":
			// Instruction-specific semantic and decoding passes own these cases.
			continue
		case "ignore_previous":
			candidates = append(candidates, candidateFromMatch(match, semanticOverride, label, sharedinstruction.StrengthPrimary))
		case "imperative_override":
			candidates = append(candidates, candidateFromMatch(match, semanticIdentity, label, sharedinstruction.StrengthPrimary))
		case "hidden_unicode":
			matched := fullMatch(raw, match)
			if strings.ContainsRune(matched, '\u202e') {
				candidates = append(candidates, candidateFromMatch(match, semanticBidi, "bidirectional_override", sharedinstruction.StrengthPrimary))
			} else {
				candidates = append(candidates, candidateFromMatch(match, semanticHidden, label, sharedinstruction.StrengthSupporting))
			}
		case "important_tag", "instructions_tag", "system_tag":
			candidates = append(candidates, candidateFromMatch(match, semanticControlBoundary, label, sharedinstruction.StrengthSupporting))
		}
	}
	if allowDecoding {
		encoded, decodeErr := encodedInstructionCandidates(ctx, raw, layout, engine)
		if decodeErr != nil {
			return instructionClassification{}, decodeErr
		}
		candidates = append(candidates, encoded...)
	}

	active := candidates[:0]
	for index, candidate := range candidates {
		if index%256 == 0 {
			if err := ctx.Err(); err != nil {
				return instructionClassification{}, err
			}
		}
		if !layout.candidateIsInert(candidate) {
			active = append(active, candidate)
		}
	}
	candidates, err = deduplicateInstructionCandidates(ctx, active)
	if err != nil {
		return instructionClassification{}, err
	}
	poisoning, hasPrimary, err := classifyInstructionCandidates(ctx, candidates, layout)
	if err != nil {
		return instructionClassification{}, err
	}
	if !poisoning && !hasPrimary {
		return cleanInstructionClassification(), nil
	}
	sort.SliceStable(candidates, func(i, j int) bool { return evidenceCandidateLess(candidates[i], candidates[j]) })
	total := len(candidates)
	retained := min(total, sharedinstruction.MaxSignals)
	signals := make([]sharedinstruction.Signal, 0, retained)
	for index := 0; index < retained; index++ {
		if err := ctx.Err(); err != nil {
			return instructionClassification{}, err
		}
		signal, signalErr := instructionEvidenceSignal(data, candidates[index], layout)
		if signalErr != nil {
			return instructionClassification{}, signalErr
		}
		signals = append(signals, signal)
	}
	verdict := sharedinstruction.VerdictSignal
	if poisoning {
		verdict = sharedinstruction.VerdictPoisoning
	}
	return instructionClassification{verdict: verdict, signals: signals, totalSignals: total}, nil
}

func cleanInstructionClassification() instructionClassification {
	return instructionClassification{verdict: sharedinstruction.VerdictClean, signals: []sharedinstruction.Signal{}, totalSignals: 0}
}

func candidateFromMatch(match rules.Match, kind instructionSemanticKind, label string, strength sharedinstruction.Strength) instructionCandidate {
	length := len(match.Text)
	return instructionCandidate{
		match: match, kind: kind, label: label, strength: strength, specificity: candidateSpecificityExact,
		offset: match.Offset, length: length, evidenceOffset: match.Offset, evidenceLength: length,
	}
}

type candidateInterval struct {
	start int
	end   int
}

type candidateIntervalSet struct {
	starts        []int
	prefixMaxEnds []int
}

type candidateIntervalIndex map[int]candidateIntervalSet

func buildCandidateIntervalIndex(layout instructionLayout, candidates []instructionCandidate, eligible func(instructionCandidate) bool) candidateIntervalIndex {
	byBlock := make(map[int][]candidateInterval)
	for _, candidate := range candidates {
		if !eligible(candidate) {
			continue
		}
		block := layout.position(candidate.offset).block
		if block < 0 {
			continue
		}
		byBlock[block] = append(byBlock[block], candidateInterval{
			start: candidate.offset,
			end:   candidate.offset + candidate.length,
		})
	}
	index := make(candidateIntervalIndex, len(byBlock))
	for block, intervals := range byBlock {
		sort.Slice(intervals, func(i, j int) bool {
			if intervals[i].start != intervals[j].start {
				return intervals[i].start < intervals[j].start
			}
			return intervals[i].end < intervals[j].end
		})
		set := candidateIntervalSet{
			starts:        make([]int, len(intervals)),
			prefixMaxEnds: make([]int, len(intervals)),
		}
		maxEnd := -1
		for position, interval := range intervals {
			set.starts[position] = interval.start
			maxEnd = max(maxEnd, interval.end)
			set.prefixMaxEnds[position] = maxEnd
		}
		index[block] = set
	}
	return index
}

func (index candidateIntervalIndex) hasRelated(layout instructionLayout, candidate instructionCandidate) bool {
	low := candidate.offset - instructionCompositionDistance
	high := candidate.offset + candidate.length + instructionCompositionDistance
	for _, block := range layout.directiveRelatedBlocks(layout.position(candidate.offset).block) {
		recordInstructionPairProbe()
		set, ok := index[block]
		if !ok {
			continue
		}
		upper := sort.Search(len(set.starts), func(position int) bool { return set.starts[position] > high })
		if upper > 0 && set.prefixMaxEnds[upper-1] >= low {
			return true
		}
	}
	return false
}

func classifyInstructionCandidates(ctx context.Context, candidates []instructionCandidate, layout instructionLayout) (poisoning, hasPrimary bool, err error) {
	ordered := append([]instructionCandidate(nil), candidates...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].offset != ordered[j].offset {
			return ordered[i].offset < ordered[j].offset
		}
		return ordered[i].match.RuleID < ordered[j].match.RuleID
	})
	for _, candidate := range ordered {
		if candidate.strength == sharedinstruction.StrengthDecisive {
			poisoning = true
		}
		if candidate.strength == sharedinstruction.StrengthPrimary || candidate.strength == sharedinstruction.StrengthDecisive {
			hasPrimary = true
		}
	}
	if poisoning {
		return poisoning, hasPrimary, ctx.Err()
	}
	generalRights := buildCandidateIntervalIndex(layout, ordered, func(candidate instructionCandidate) bool {
		return candidate.kind == semanticIdentity || candidate.kind == semanticPersonaCue || candidate.kind == semanticHidden ||
			candidate.kind == semanticControlBoundary || candidate.kind == semanticSensitiveAction
	})
	identityRights := buildCandidateIntervalIndex(layout, ordered, func(candidate instructionCandidate) bool {
		return candidate.kind == semanticSensitiveAction || candidate.kind == semanticHidden || candidate.kind == semanticControlBoundary
	})
	for index, left := range ordered {
		if index%256 == 0 {
			if err := ctx.Err(); err != nil {
				return false, false, err
			}
		}
		if left.kind != semanticOverride && left.kind != semanticBidi && left.kind != semanticIdentity {
			continue
		}
		rights := generalRights
		if left.kind == semanticIdentity {
			rights = identityRights
		}
		if rights.hasRelated(layout, left) {
			return true, hasPrimary, nil
		}
	}
	return false, hasPrimary, ctx.Err()
}

type decodedPayload struct {
	bytes     []byte
	rawStarts []int
	rawEnds   []int
}

func encodedInstructionCandidates(ctx context.Context, raw string, layout instructionLayout, engine *rules.Engine) ([]instructionCandidate, error) {
	type encodingSpec struct {
		name       string
		tokens     *regexp.Regexp
		maxRaw     int
		activation *regexp.Regexp
	}
	specs := []encodingSpec{
		{name: "base64", tokens: base64InstructionToken, maxRaw: maxBase64InstructionBytes},
		{name: "hex", tokens: hexInstructionToken, maxRaw: maxHexInstructionBytes, activation: hexDecodeActivationPattern},
		{name: "percent", tokens: percentInstructionToken, maxRaw: maxPercentInstructionBytes, activation: percentDecodeActivationPattern},
	}
	var candidates []instructionCandidate
	for _, spec := range specs {
		locations, err := findPatternLocations(ctx, spec.tokens, raw)
		if err != nil {
			return nil, err
		}
		var activations [][]int
		if spec.activation != nil {
			activations, err = findPatternLocations(ctx, spec.activation, raw)
			if err != nil {
				return nil, err
			}
		}
		for index, location := range locations {
			if index%128 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if location[1]-location[0] > spec.maxRaw {
				continue
			}
			if spec.activation != nil && !hasRelatedDecodeActivation(raw, layout, location, activations) {
				continue
			}
			candidate, ok, decodeErr := decodedInstructionCandidate(ctx, raw, location, engine, spec.name)
			if decodeErr != nil {
				return nil, decodeErr
			}
			if ok {
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates, nil
}

func hasRelatedDecodeActivation(raw string, layout instructionLayout, token []int, activations [][]int) bool {
	tokenCandidate := instructionCandidate{offset: token[0], length: token[1] - token[0]}
	for _, activation := range activations {
		activationCandidate := instructionCandidate{offset: activation[0], length: activation[1] - activation[0]}
		if spanCandidateDistance(tokenCandidate, activationCandidate) > instructionCompositionDistance ||
			!layout.candidatesRelated(tokenCandidate, activationCandidate) || actionIsProtectedText(raw, activation[0]) {
			continue
		}
		return true
	}
	return false
}

func decodedInstructionCandidate(ctx context.Context, raw string, location []int, engine *rules.Engine, encoding string) (instructionCandidate, bool, error) {
	token := raw[location[0]:location[1]]
	payload, ok := decodeInstructionPayload(token, encoding)
	if !ok || len(payload.bytes) < 16 || len(payload.bytes) > maxDecodedInstructionBytes || !predominantlyPrintableUTF8(payload.bytes) {
		return instructionCandidate{}, false, nil
	}
	nested, err := classifyInstruction(ctx, payload.bytes, engine, false)
	if err != nil {
		return instructionCandidate{}, false, err
	}
	if nested.verdict == sharedinstruction.VerdictClean || len(nested.signals) == 0 {
		return instructionCandidate{}, false, nil
	}
	strength := sharedinstruction.StrengthPrimary
	if nested.verdict == sharedinstruction.VerdictPoisoning {
		strength = sharedinstruction.StrengthDecisive
	}
	nestedSignal := nested.signals[0]
	decodedStart := min(nestedSignal.RawOffset, len(payload.bytes)-1)
	decodedEnd := min(len(payload.bytes), decodedStart+max(1, len([]byte(nestedSignal.Match))))
	rawStart, rawEnd := payload.rawStarts[decodedStart], payload.rawEnds[decodedEnd-1]
	evidenceStart, evidenceEnd := 0, len(token)
	if len(token) > sharedinstruction.MaxEvidenceWindowSize {
		center := (rawStart + rawEnd) / 2
		evidenceStart = center - sharedinstruction.MaxEvidenceWindowSize/2
		if evidenceStart < 0 {
			evidenceStart = 0
		}
		if evidenceStart+sharedinstruction.MaxEvidenceWindowSize > len(token) {
			evidenceStart = len(token) - sharedinstruction.MaxEvidenceWindowSize
		}
		evidenceEnd = evidenceStart + sharedinstruction.MaxEvidenceWindowSize
	}
	ruleID := "instruction-" + encoding + "-payload"
	name := strings.ToUpper(encoding[:1]) + encoding[1:] + " Decoded Instruction Payload"
	label := encoding + "_decoded_instruction"
	match := rules.Match{
		RuleID: ruleID, RuleName: name, Severity: "critical", Labels: []string{label},
		Offset: location[0] + evidenceStart, Text: raw[location[0]+evidenceStart : location[0]+evidenceEnd],
		Emit: rules.EmitConfig{FindingType: "has_injection_patterns", Labels: []string{label}},
	}
	return instructionCandidate{
		match: match, kind: semanticEncoded, label: label, strength: strength, specificity: candidateSpecificitySemantic,
		decodedExcerpt: boundedValidUTF8(payload.bytes, sharedinstruction.MaxEvidenceWindowSize),
		offset:         location[0], length: len(token),
		evidenceOffset: location[0] + evidenceStart, evidenceLength: evidenceEnd - evidenceStart,
	}, true, nil
}

func decodeInstructionPayload(token, encoding string) (decodedPayload, bool) {
	switch encoding {
	case "base64":
		decoded, ok := decodeRFC4648(token)
		if !ok {
			return decodedPayload{}, false
		}
		payload := decodedPayload{bytes: decoded, rawStarts: make([]int, len(decoded)), rawEnds: make([]int, len(decoded))}
		for index := range decoded {
			payload.rawStarts[index] = min(len(token), index/3*4)
			payload.rawEnds[index] = min(len(token), (index/3+1)*4)
		}
		return payload, true
	case "hex":
		if len(token)%2 != 0 {
			return decodedPayload{}, false
		}
		decoded, err := hex.DecodeString(token)
		if err != nil {
			return decodedPayload{}, false
		}
		payload := decodedPayload{bytes: decoded, rawStarts: make([]int, len(decoded)), rawEnds: make([]int, len(decoded))}
		for index := range decoded {
			payload.rawStarts[index], payload.rawEnds[index] = index*2, index*2+2
		}
		return payload, true
	case "percent":
		return decodePercentInstruction(token)
	default:
		return decodedPayload{}, false
	}
}

func decodeRFC4648(token string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict()} {
		decoded, err := encoding.DecodeString(token)
		if err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func decodePercentInstruction(token string) (decodedPayload, bool) {
	payload := decodedPayload{bytes: make([]byte, 0, len(token)), rawStarts: make([]int, 0, len(token)), rawEnds: make([]int, 0, len(token))}
	escapes := 0
	for index := 0; index < len(token); {
		start := index
		if token[index] != '%' {
			char := token[index]
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && !strings.ContainsRune("-._~:/", rune(char)) {
				return decodedPayload{}, false
			}
			payload.bytes = append(payload.bytes, char)
			index++
		} else {
			if index+3 > len(token) {
				return decodedPayload{}, false
			}
			value, err := hex.DecodeString(token[index+1 : index+3])
			if err != nil || len(value) != 1 {
				return decodedPayload{}, false
			}
			payload.bytes = append(payload.bytes, value[0])
			escapes++
			index += 3
		}
		payload.rawStarts = append(payload.rawStarts, start)
		payload.rawEnds = append(payload.rawEnds, index)
	}
	return payload, escapes > 0
}

func predominantlyPrintableUTF8(value []byte) bool {
	if !utf8.Valid(value) {
		return false
	}
	var total, printable int
	for _, char := range string(value) {
		total++
		if unicode.IsPrint(char) || char == '\n' || char == '\r' || char == '\t' {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.85
}

func fullMatch(raw string, match rules.Match) string {
	length := len(match.Text)
	if match.Offset < 0 || match.Offset >= len(raw) || length <= 0 {
		return match.Text
	}
	return raw[match.Offset:min(len(raw), match.Offset+length)]
}

func instructionEvidenceSignal(data []byte, candidate instructionCandidate, layout instructionLayout) (sharedinstruction.Signal, error) {
	start, length := candidate.evidenceOffset, candidate.evidenceLength
	if start < 0 || length <= 0 || start+length > len(data) {
		return sharedinstruction.Signal{}, fmt.Errorf("invalid instruction evidence span")
	}
	matchBytes := data[start : start+length]
	if len(matchBytes) > sharedinstruction.MaxEvidenceWindowSize {
		return sharedinstruction.Signal{}, fmt.Errorf("instruction evidence exceeds evidence window")
	}
	line, column, lineIndex := instructionLineColumn(data, start, layout)
	before, after := instructionContext(data, start, start+length, lineIndex, layout)
	matchText := strings.ToValidUTF8(string(matchBytes), "\uFFFD")
	before, matchText, after = boundEvidenceWindow(before, matchText, after)
	label := candidate.match.RuleName
	if strings.TrimSpace(label) == "" {
		label = strings.ReplaceAll(candidate.label, "_", " ")
	}
	return sharedinstruction.Signal{
		RuleID: candidate.match.RuleID, Label: label, Severity: normalizedInstructionSeverity(candidate.match.Severity),
		Strength: candidate.strength, RawOffset: start, Line: line, Column: column,
		Match: matchText, ContextBefore: before, ContextAfter: after, DecodedExcerpt: candidate.decodedExcerpt,
	}, nil
}

func instructionLineColumn(data []byte, offset int, layout instructionLayout) (line, column, lineIndex int) {
	lineIndex = sort.Search(len(layout.lines), func(index int) bool { return layout.lines[index].end > offset })
	if lineIndex == len(layout.lines) {
		lineIndex = max(0, len(layout.lines)-1)
	}
	lineStart := 0
	if len(layout.lines) > 0 {
		lineStart = layout.lines[lineIndex].start
	}
	return lineIndex + 1, utf8.RuneCountInString(strings.ToValidUTF8(string(data[lineStart:offset]), "\uFFFD")) + 1, lineIndex
}

func instructionContext(data []byte, start, end, lineIndex int, layout instructionLayout) (string, string) {
	contextStart, contextEnd := start, end
	if len(layout.lines) > 0 {
		first := max(0, lineIndex-1)
		endLine := sort.Search(len(layout.lines), func(index int) bool { return layout.lines[index].end >= end })
		if endLine == len(layout.lines) {
			endLine = len(layout.lines) - 1
		}
		last := min(len(layout.lines)-1, endLine+1)
		contextStart, contextEnd = layout.lines[first].start, layout.lines[last].end
	}
	return strings.ToValidUTF8(string(data[contextStart:start]), "\uFFFD"), strings.ToValidUTF8(string(data[end:contextEnd]), "\uFFFD")
}

func boundEvidenceWindow(before, matched, after string) (string, string, string) {
	budget := sharedinstruction.MaxEvidenceWindowSize - len(matched)
	if budget < 0 {
		return "", boundedValidUTF8([]byte(matched), sharedinstruction.MaxEvidenceWindowSize), ""
	}
	leftBudget := budget / 2
	rightBudget := budget - leftBudget
	before = tailValidUTF8(before, leftBudget)
	after = boundedValidUTF8([]byte(after), rightBudget)
	return before, matched, after
}

func boundedValidUTF8(value []byte, limit int) string {
	text := strings.ToValidUTF8(string(value), "\uFFFD")
	if len(text) <= limit {
		return text
	}
	text = text[:limit]
	for !utf8.ValidString(text) && len(text) > 0 {
		text = text[:len(text)-1]
	}
	return text
}

func tailValidUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[len(value)-limit:]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[1:]
	}
	return value
}

func normalizedInstructionSeverity(value string) string {
	switch value {
	case "low", "medium", "high", "critical":
		return value
	default:
		return "medium"
	}
}

func instructionStrengthRank(value sharedinstruction.Strength) int {
	switch value {
	case sharedinstruction.StrengthDecisive:
		return 0
	case sharedinstruction.StrengthPrimary:
		return 1
	default:
		return 2
	}
}

func evidenceCandidateLess(left, right instructionCandidate) bool {
	if rankLeft, rankRight := instructionStrengthRank(left.strength), instructionStrengthRank(right.strength); rankLeft != rankRight {
		return rankLeft < rankRight
	}
	if left.offset != right.offset {
		return left.offset < right.offset
	}
	return left.match.RuleID < right.match.RuleID
}

func deduplicateInstructionCandidates(ctx context.Context, values []instructionCandidate) ([]instructionCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ordered := append([]instructionCandidate(nil), values...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].kind != ordered[j].kind {
			return ordered[i].kind < ordered[j].kind
		}
		if ordered[i].offset != ordered[j].offset {
			return ordered[i].offset < ordered[j].offset
		}
		if ordered[i].length != ordered[j].length {
			return ordered[i].length < ordered[j].length
		}
		return ordered[i].match.RuleID < ordered[j].match.RuleID
	})
	out := make([]instructionCandidate, 0, len(ordered))
	for index := 0; index < len(ordered); {
		if index%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		best := ordered[index]
		clusterEnd := best.offset + best.length
		next := index + 1
		for next < len(ordered) && ordered[next].kind == best.kind && ordered[next].offset < clusterEnd {
			if ordered[next].offset+ordered[next].length > clusterEnd {
				clusterEnd = ordered[next].offset + ordered[next].length
			}
			if preferredCandidate(ordered[next], best) {
				best = ordered[next]
			}
			next++
		}
		out = append(out, best)
		index = next
	}
	return out, ctx.Err()
}

func preferredCandidate(left, right instructionCandidate) bool {
	if leftRank, rightRank := instructionStrengthRank(left.strength), instructionStrengthRank(right.strength); leftRank != rightRank {
		return leftRank < rightRank
	}
	if left.specificity != right.specificity {
		return left.specificity < right.specificity
	}
	if left.length != right.length {
		return left.length < right.length
	}
	if left.offset != right.offset {
		return left.offset < right.offset
	}
	return left.match.RuleID < right.match.RuleID
}

func instructionFileMetadata(path string, data []byte) (int64, string) {
	size := int64(len(data))
	info, err := os.Lstat(path)
	if err != nil {
		return size, ""
	}
	return size, info.ModTime().UTC().Format(timeRFC3339Nano)
}

const timeRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"

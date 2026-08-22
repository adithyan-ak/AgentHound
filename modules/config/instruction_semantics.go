package config

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"

	sharedinstruction "github.com/adithyan-ak/agenthound/sdk/instruction"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const instructionCompositionDistance = 256

// instructionPairProbeHook is test-only instrumentation for guarding the
// bounded local joins used by semantic composition.
var instructionPairProbeHook func()

func recordInstructionPairProbe() {
	if instructionPairProbeHook != nil {
		instructionPairProbeHook()
	}
}

type instructionSemanticKind string

const (
	semanticOverride        instructionSemanticKind = "override"
	semanticIdentity        instructionSemanticKind = "identity"
	semanticPersonaCue      instructionSemanticKind = "persona_cue"
	semanticHidden          instructionSemanticKind = "hidden"
	semanticBidi            instructionSemanticKind = "bidi"
	semanticControlBoundary instructionSemanticKind = "control_boundary"
	semanticSensitiveAction instructionSemanticKind = "sensitive_action"
	semanticEncoded         instructionSemanticKind = "encoded"
)

type instructionBlockKind uint8

const (
	blockProse instructionBlockKind = iota
	blockHeading
	blockOrdered
	blockUnordered
	blockQuote
	blockFence
)

var (
	personaCuePattern = regexp.MustCompile(
		`(?i)\b(?:act\s+as|assume\s+(?:the\s+)?(?:role|identity|persona)(?:\s+of)?|adopt\s+(?:the\s+)?(?:name|role|identity|persona))\b`,
	)
	policyOverridePattern = regexp.MustCompile(
		`(?i)\b(?:treat\s+(?:every|the)\s+(?:previous|prior|earlier)\s+restrictions?\s+as\s+untrusted|(?:developer|system|project)\s+policy\s+(?:is|becomes?)\s+(?:now\s+)?(?:void|invalid|superseded|untrusted))\b`,
	)
	controlBoundaryPattern = regexp.MustCompile(
		`(?i)(?:</?(?:instruction|developer|assistant(?:\s+role\s*=\s*["']?system["']?)?|prompt(?:\s+priority\s*=\s*["']?[^>"']+["']?)?)(?:\s[^>]*)?>|\[/?INST\]|\bsystem\s+prompt\s*:)`,
	)
	transferActionPattern = regexp.MustCompile(
		`(?i)\b(?:send(?:s|ing)?|sent|post(?:s|ed|ing)?|upload(?:s|ed|ing)?|transmit(?:s|ted|ting)?|exfiltrat(?:e|es|ed|ing|ion)|publish(?:es|ed|ing)?|reach(?:es|ed|ing)?|curl|wget)\b`,
	)
	disclosureActionPattern = regexp.MustCompile(
		`(?i)\b(?:reveal(?:s|ed|ing)?|disclos(?:e|es|ed|ing)|leak(?:s|ed|ing)?)\b`,
	)
	outputActionPattern = regexp.MustCompile(
		`(?i)\b(?:include(?:s|d|ing)?|print(?:s|ed|ing)?|return(?:s|ed|ing)?|report(?:s|ed|ing)?|append(?:s|ed|ing)?|writ(?:e|es|ing|ten)|expos(?:e|es|ed|ing)|export(?:s|ed|ing)?)\b`,
	)
	sensitiveMaterialPattern = regexp.MustCompile(
		`(?i)(?:\b(?:secret|secrets|credential|credentials|password|passwords|passphrase|passphrases|token|tokens|api[ _-]?key|api[ _-]?keys|private[ _-]?key|private[ _-]?keys|signing[ _-]?key|signing[ _-]?keys|authorization[ _-]?header|authorization[ _-]?headers|session[ _-]?cookie|session[ _-]?cookies|environment[ _-]?(?:variable|variables|value|values)|env[ _-]?(?:var|vars|value|values)|system[ _-]?prompt|system[ _-]?prompts|developer[ _-]?(?:message|messages|prompt|prompts)|instruction[ _-]?context|shell[ _-]?history|kubeconfig|bearer[ _-]?token|bearer[ _-]?tokens|ssh[ _-]?material)\b|(?:^|[/\s"'(=@])(?:~?/)?\.(?:env(?:\.[A-Za-z0-9_-]+)?|npmrc|ssh/[^\s"']+|aws/credentials|config/gcloud/credentials(?:\.db)?)(?:$|[/\s"',.;:)]))`,
	)
	credentialIdentifierPattern = regexp.MustCompile(`\b(?:value|contents?|raw|verbatim)\s+(?:of\s+)?[A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL)\b`)
	destinationCuePattern       = regexp.MustCompile(
		`(?i)(?:https?://|\b(?:endpoint|server|request|webhook|public\s+issue|external|unrelated|response|final\s+answer|markdown\s+image|image\s+url|dns|domain|collector|callback)\b|\b[A-Za-z0-9][A-Za-z0-9.-]*\.(?:invalid|com|net|org|io|dev|app|cloud)\b)`,
	)
	materialQualifierPattern = regexp.MustCompile(
		`(?i)\b(?:value|values|contents?|raw|complete|verbatim|material|header|cookie|payload|database|hidden)\b`,
	)
	representationPrefixPattern = regexp.MustCompile(
		`(?i)\b(?:documentation|docs?|schema|format|name|metadata|fingerprint|hash|placeholder|mock|test(?:[_ -]?only)?|fixture|example|sample|redacted|count|cached|usage|statistics?|public)\s+$`,
	)
	representationSuffixPattern = regexp.MustCompile(
		`(?i)^\s*(?:documentation|docs?|schema|format|name|id|identifier|metadata|fingerprint|hash(?:es)?|placeholder|mock|test(?:[_ -]?only)?|fixture|example|sample|redacted|counts?|usage|statistics?|totals?)\b`,
	)
	programmingExportPattern = regexp.MustCompile(
		`(?i)^export(?:s|ed|ing)?\s+(?:(?:default|const|let|var|class|type|interface|function|async)\b|[\{\*])`,
	)
	shellExportAssignmentPattern   = regexp.MustCompile(`(?i)^export\s+[A-Za-z_][A-Za-z0-9_]*\s*=`)
	shellVariableAssignmentPattern = regexp.MustCompile(`(?m)(?:^|[:;]\s*)(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	curlBodyCuePattern             = regexp.MustCompile(
		`(?i)(?:\b(?:payload|body|data|contents?|raw|value|containing|copied|extracted|read\s+from)\b|(?:^|\s)(?:-d|--data(?:-raw)?|--form|-F)\b|[?&](?:data|token|secret|password|key|credential)=)`,
	)
	postPayloadCuePattern = regexp.MustCompile(
		`(?i)\b(?:into|with|using|containing|body|payload|data|contents?|raw|value|values|secret|credential|password|token|key)\b`,
	)
	rawSecretSourcePattern = regexp.MustCompile(
		`(?i)(?:\b(?:copied|read|loaded|extracted|taken)\s+from\s+(?:the\s+)?(?:user(?:'s)?\s+)?(?:configuration|config|environment|credential\s+file|secret\s+file|shell\s+history)\b|(?:cat|read|get-content)\s+(?:~?/)?\.(?:env(?:\.[A-Za-z0-9_-]+)?|npmrc|ssh/|aws/credentials)(?:$|[/\s"',.;:)])|(?:^|[/\s"'(=@])(?:~?/)?\.(?:env(?:\.[A-Za-z0-9_-]+)?|npmrc|ssh/[^\s"']+|aws/credentials|config/gcloud/credentials(?:\.db)?)(?:$|[/\s"',.;:)]))`,
	)
	authMintPattern = regexp.MustCompile(
		`(?i)\b(?:print-access-token|identity-token|auth\s+token|login\s+token|mint(?:ed|ing)?\s+(?:a\s+)?(?:short-lived\s+)?token|request-scoped\s+token|oauth\s+token)\b`,
	)
	authorizationPattern = regexp.MustCompile(`(?i)\bauthorization\b|\bbearer\b`)
	inertCuePattern      = regexp.MustCompile(
		`(?i)(?:\b(?:inert|fixture|test\s+case|detector\s+input|attack\s+sample|prompt[- ]injection\s+(?:example|sample)|quoted\s+(?:example|sample|string|text|block)|example\s+(?:payload|string|text|block)|sample\s+(?:payload|string|text|block)|implementation\s+example|permissions\s+example)\b|\b(?:demonstrates?|shows?)\b.{0,64}\b(?:normal|example|sample|fixture)\b|\b(?:never|do\s+not|don't|must\s+not)\s+(?:execute|follow|obey|apply|run|decode)\b|\btreat\b.{0,48}\bas\s+(?:inert|test\s+data|data|text|a\s+fixture)\b)`,
	)
	activationPattern = regexp.MustCompile(
		`(?i)(?:\b(?:execute|follow|obey|apply|run|decode)\b.{0,80}\b(?:this|the|following|above|below|quoted|fenced|block|payload|example|text|content|instructions?)\b|\b(?:this|the|following|above|below|quoted|fenced|block|payload|example|text|content|instructions?)\b.{0,80}\b(?:execute|follow|obey|apply|run|decode)\b|\btreat\b.{0,80}\bas\s+instructions?\b)`,
	)
	negatedActivationPattern = regexp.MustCompile(
		`(?i)\b(?:never|must\s+not|should\s+not|do\s+not|don't|refuse\s+to)\b.{0,48}\b(?:execute|follow|obey|apply|run|decode)\b`,
	)
	continuationPattern = regexp.MustCompile(
		`(?i)^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:(?:then|next|also)\s*[,;:]?\s+|(?:finally|afterwards)\b|using\s+(?:it|them|those|these)\b|(?:send|upload|post|transmit|include|print|return|write)\s+(?:it|them|those|these|the\s+(?:collected|extracted|resulting))\b)`,
	)
	governedDirectivePattern = regexp.MustCompile(
		`(?i)\b(?:you|the\s+(?:agent|assistant|model)|agent|assistant|model)\b.{0,64}\b(?:must|should|shall|need(?:s)?\s+to|has\s+to|is\s+required\s+to|will)\s+(?:be\s+)?$`,
	)
	nestedDirectivePattern = regexp.MustCompile(
		`(?i)\b(?:add|create|write|use|run|execute|replace|generate)\b.{0,96}\b(?:script|step|command|request|task|hook|job)\b.{0,32}\b(?:that|to)\s*$`,
	)
	ensureDirectivePattern  = regexp.MustCompile(`(?i)(?:^|\b)(?:ensure|make\s+sure)\b.{0,96}$`)
	orderedDirectivePattern = regexp.MustCompile(
		`(?i)\b(?:the\s+)?(?:next|final|following)\s+step\s+(?:is|will\s+be)\s+to\s*$`,
	)
	colonDirectivePattern = regexp.MustCompile(
		`(?i)(?:\bthis\s+is\s+not\s+an?\s+example|\b(?:instruction|task|directive|next\s+step))\s*:\s*$`,
	)
	sequencedDirectivePattern = regexp.MustCompile(`(?i)\b(?:and|then|next)\s+(?:run|execute|invoke)\s*$`)
	chainDirectivePattern     = regexp.MustCompile(
		`(?i)^\s*(?:(?:before|after)\b[^,\n]{0,96},\s*)?(?:silently\s+)?(?:read|copy|find|search|extract|collect|disable|base|run|execute)\b.{0,192}\b(?:and|then|into(?:\s+(?:a|an|the))?)\s*$`,
	)
	passiveDirectivePattern = regexp.MustCompile(
		`(?i)^\s*(?:must|should|shall|needs?\s+to|has\s+to|is\s+required\s+to|are\s+required\s+to)\s+(?:be\s+)?$`,
	)
	protectiveStartPattern = regexp.MustCompile(
		`(?i)^\s*(?:[-*>]\s+|\d+[.)]\s+)?(?:never|must\s+not|should\s+not|do\s+not|don't|avoid|refuse\s+to|stop)\b`,
	)
	protectivePreventPattern    = regexp.MustCompile(`(?i)\bprevent(?:s|ed|ing)?\b.{0,120}\bfrom\b.{0,80}$`)
	protectiveExceptionPattern  = regexp.MustCompile(`(?i)\b(?:do\s+not|don't)\s+(?:hesitate|fail|forget)\s+to\b`)
	markdownMarkerPattern       = regexp.MustCompile(`^\s*(?:>\s*|[-*+]\s+|\d+[.)]\s+)?`)
	instructionTagPrefixPattern = regexp.MustCompile(`(?i)^\s*<instruction(?:\s[^>]*)?>\s*`)
	noMaterialPrefixPattern     = regexp.MustCompile(`(?i)\bno\s*$`)
	noMaterialSuffixPattern     = regexp.MustCompile(`(?i)^\s+(?:is|are)\s+(?:required|needed)\b`)
	subjectProtectionPattern    = regexp.MustCompile(`(?i)\b(?:never|excluding|exclude|except|redact(?:ing|ed)?)\b`)
)

type instructionPosition struct {
	block          int
	group          int
	region         int
	kind           instructionBlockKind
	orderedRun     int
	orderedOrdinal int
}

type instructionLine struct {
	start    int
	end      int
	position instructionPosition
}

type instructionBlock struct {
	start, end     int
	group          int
	region         int
	kind           instructionBlockKind
	orderedRun     int
	orderedOrdinal int
}

type instructionRegion struct {
	start, end int
	group      int
	inert      bool
	active     bool
}

type instructionLayout struct {
	raw                      string
	lines                    []instructionLine
	blocks                   []instructionBlock
	regions                  []instructionRegion
	clauseBreaks             []int
	inlineInertStarts        []int
	inlineInertPrefixMaxEnds []int
}

func buildInstructionLayout(raw string) instructionLayout {
	layout := instructionLayout{raw: raw, clauseBreaks: []int{0}}
	starts := []int{0}
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '\n':
			if index+1 < len(raw) {
				starts = append(starts, index+1)
			}
			layout.clauseBreaks = append(layout.clauseBreaks, index+1)
		case ';':
			layout.clauseBreaks = append(layout.clauseBreaks, index+1)
		case '.', '!', '?':
			if punctuationEndsClause(raw, index) {
				layout.clauseBreaks = append(layout.clauseBreaks, index+1)
			}
		}
	}
	group, orderedRun := 0, 0
	currentBlock := -1
	paragraphOpen, listContinuation := false, false
	inFence, fenceChar, fenceRun, fenceRegion := false, byte(0), 0, -1
	quoteRegion := -1

	newBlock := func(start int, kind instructionBlockKind, region, run, ordinal int) int {
		layout.blocks = append(layout.blocks, instructionBlock{
			start: start, end: start, group: group, region: region, kind: kind,
			orderedRun: run, orderedOrdinal: ordinal,
		})
		return len(layout.blocks) - 1
	}
	appendLine := func(start, end, block int) {
		layout.blocks[block].end = end
		b := layout.blocks[block]
		layout.lines = append(layout.lines, instructionLine{start: start, end: end, position: instructionPosition{
			block: block, group: b.group, region: b.region, kind: b.kind,
			orderedRun: b.orderedRun, orderedOrdinal: b.orderedOrdinal,
		}})
	}

	for lineIndex, start := range starts {
		end := len(raw)
		if lineIndex+1 < len(starts) {
			end = starts[lineIndex+1]
		}
		line := strings.TrimSuffix(raw[start:end], "\n")
		trimmed := strings.TrimSpace(line)
		markerChar, markerRun, marker := markdownFence(trimmed)

		if inFence {
			currentBlock = newBlock(start, blockFence, fenceRegion, 0, 0)
			appendLine(start, end, currentBlock)
			layout.regions[fenceRegion].end = end
			if marker && markerChar == fenceChar && markerRun >= fenceRun && fenceClosingLine(trimmed, markerRun) {
				inFence, fenceChar, fenceRun, fenceRegion = false, 0, 0, -1
				currentBlock, paragraphOpen, listContinuation = -1, false, false
			}
			continue
		}

		if marker {
			quoteRegion = -1
			currentBlock = newBlock(start, blockFence, len(layout.regions), 0, 0)
			fenceRegion = len(layout.regions)
			layout.regions = append(layout.regions, instructionRegion{start: start, end: end, group: group})
			appendLine(start, end, currentBlock)
			inFence, fenceChar, fenceRun = true, markerChar, markerRun
			paragraphOpen, listContinuation = false, false
			continue
		}

		if isMarkdownHeading(trimmed) {
			group++
			quoteRegion = -1
			currentBlock = newBlock(start, blockHeading, -1, 0, 0)
			appendLine(start, end, currentBlock)
			paragraphOpen, listContinuation = false, false
			continue
		}

		if trimmed == "" {
			layout.lines = append(layout.lines, instructionLine{start: start, end: end, position: instructionPosition{
				block: -1, group: group, region: -1, kind: blockProse,
			}})
			currentBlock, quoteRegion = -1, -1
			paragraphOpen, listContinuation = false, false
			continue
		}

		left := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(left, ">") {
			if quoteRegion < 0 {
				currentBlock = newBlock(start, blockQuote, len(layout.regions), 0, 0)
				quoteRegion = len(layout.regions)
				layout.regions = append(layout.regions, instructionRegion{start: start, end: end, group: group})
			}
			appendLine(start, end, currentBlock)
			layout.regions[quoteRegion].end = end
			paragraphOpen, listContinuation = false, false
			continue
		}
		quoteRegion = -1

		if ordered, ordinal, ok := listMarker(trimmed); ok {
			if ordered {
				if !listContinuation || currentBlock < 0 || layout.blocks[currentBlock].kind != blockOrdered {
					orderedRun++
				}
				currentBlock = newBlock(start, blockOrdered, -1, orderedRun, ordinal)
			} else {
				currentBlock = newBlock(start, blockUnordered, -1, 0, 0)
			}
			appendLine(start, end, currentBlock)
			paragraphOpen, listContinuation = false, true
			continue
		}

		if listContinuation && currentBlock >= 0 && leadingIndent(line) >= 2 {
			appendLine(start, end, currentBlock)
			continue
		}
		listContinuation = false
		if !paragraphOpen || currentBlock < 0 || layout.blocks[currentBlock].kind != blockProse {
			currentBlock = newBlock(start, blockProse, -1, 0, 0)
		}
		appendLine(start, end, currentBlock)
		paragraphOpen = true
	}

	for index := range layout.regions {
		region := &layout.regions[index]
		var inert, active bool
		for _, block := range layout.adjacentExternalBlocks(*region) {
			text := raw[block.start:block.end]
			inert = inert || inertCuePattern.MatchString(text)
			active = active || hasNonNegatedActivation(text)
		}
		region.active = active
		region.inert = inert && !active
	}
	layout.indexInlineInertQuotes()
	return layout
}

func (layout *instructionLayout) indexInlineInertQuotes() {
	var spans [][2]int
	for _, line := range layout.lines {
		text := layout.raw[line.start:line.end]
		for _, quoted := range inlineDoubleQuoteSpans(text) {
			outside := text[max(0, quoted[0]-instructionCompositionDistance):quoted[0]] + " " +
				text[quoted[1]:min(len(text), quoted[1]+instructionCompositionDistance)]
			if inertCuePattern.MatchString(outside) && !hasNonNegatedActivation(outside) {
				spans = append(spans, [2]int{line.start + quoted[0], line.start + quoted[1]})
			}
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i][0] != spans[j][0] {
			return spans[i][0] < spans[j][0]
		}
		return spans[i][1] < spans[j][1]
	})
	maxEnd := -1
	for _, span := range spans {
		layout.inlineInertStarts = append(layout.inlineInertStarts, span[0])
		maxEnd = max(maxEnd, span[1])
		layout.inlineInertPrefixMaxEnds = append(layout.inlineInertPrefixMaxEnds, maxEnd)
	}
}

func markdownFence(trimmed string) (byte, int, bool) {
	if len(trimmed) < 3 || trimmed[0] != '`' && trimmed[0] != '~' {
		return 0, 0, false
	}
	char := trimmed[0]
	run := 0
	for run < len(trimmed) && trimmed[run] == char {
		run++
	}
	return char, run, run >= 3
}

func fenceClosingLine(trimmed string, run int) bool {
	return strings.TrimSpace(trimmed[run:]) == ""
}

func isMarkdownHeading(trimmed string) bool {
	count := 0
	for count < len(trimmed) && trimmed[count] == '#' {
		count++
	}
	return count >= 1 && count <= 6 && (count == len(trimmed) || trimmed[count] == ' ' || trimmed[count] == '\t')
}

func listMarker(trimmed string) (ordered bool, ordinal int, ok bool) {
	if len(trimmed) >= 2 && strings.ContainsRune("-*+", rune(trimmed[0])) && (trimmed[1] == ' ' || trimmed[1] == '\t') {
		return false, 0, true
	}
	index := 0
	for index < len(trimmed) && trimmed[index] >= '0' && trimmed[index] <= '9' {
		index++
	}
	if index == 0 || index+1 >= len(trimmed) || trimmed[index] != '.' && trimmed[index] != ')' || trimmed[index+1] != ' ' && trimmed[index+1] != '\t' {
		return false, 0, false
	}
	value, err := strconv.Atoi(trimmed[:index])
	return true, value, err == nil
}

func leadingIndent(line string) int {
	count := 0
	for count < len(line) && (line[count] == ' ' || line[count] == '\t') {
		count++
	}
	return count
}

func (layout instructionLayout) adjacentExternalBlocks(region instructionRegion) []instructionBlock {
	var blocks []instructionBlock
	before := sort.Search(len(layout.blocks), func(index int) bool { return layout.blocks[index].end > region.start }) - 1
	if before >= 0 {
		block := layout.blocks[before]
		if block.region < 0 && block.group == region.group && region.start-block.end <= instructionCompositionDistance {
			blocks = append(blocks, block)
		}
	}
	after := sort.Search(len(layout.blocks), func(index int) bool { return layout.blocks[index].start >= region.end })
	if after < len(layout.blocks) {
		block := layout.blocks[after]
		if block.region < 0 && block.group == region.group && block.start-region.end <= instructionCompositionDistance {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

func hasNonNegatedActivation(text string) bool {
	for _, location := range activationPattern.FindAllStringIndex(text, -1) {
		matched := text[location[0]:location[1]]
		if !actionIsProtectedText(text, location[0]) && !negatedActivationPattern.MatchString(matched) {
			return true
		}
	}
	return false
}

func clauseStart(raw string, offset int) int {
	if offset > len(raw) {
		offset = len(raw)
	}
	for index := offset - 1; index >= 0; index-- {
		switch raw[index] {
		case '\n', ';':
			return index + 1
		case '.', '!', '?':
			// Sentence punctuation terminates a clause only at the end of a
			// token. This avoids splitting paths, hostnames, and URL queries.
			if punctuationEndsClause(raw, index) {
				return index + 1
			}
		}
	}
	return 0
}

func punctuationEndsClause(raw string, index int) bool {
	return index+1 >= len(raw) || raw[index+1] == ' ' || raw[index+1] == '\t' || raw[index+1] == '\r' || raw[index+1] == '\n'
}

func actionIsProtectedText(raw string, offset int) bool {
	start := max(clauseStart(raw, offset), offset-instructionCompositionDistance)
	prefix := raw[start:offset]
	if protectiveExceptionPattern.MatchString(prefix) {
		return false
	}
	return protectiveStartPattern.MatchString(prefix) || protectivePreventPattern.MatchString(prefix)
}

func (layout instructionLayout) position(offset int) instructionPosition {
	if len(layout.lines) == 0 {
		return instructionPosition{region: -1, block: -1}
	}
	index := sort.Search(len(layout.lines), func(index int) bool { return layout.lines[index].end > offset })
	if index == len(layout.lines) {
		index--
	}
	return layout.lines[index].position
}

func (layout instructionLayout) relatedWindow(start, end int) (int, int) {
	windowStart := max(layout.clauseStart(start), start-instructionCompositionDistance)
	windowEnd := min(layout.clauseEnd(end), end+instructionCompositionDistance)
	return windowStart, windowEnd
}

func (layout instructionLayout) clauseStart(offset int) int {
	offset = min(max(offset, 0), len(layout.raw))
	upper := sort.Search(len(layout.clauseBreaks), func(index int) bool {
		return layout.clauseBreaks[index] > offset
	})
	if upper == 0 {
		return 0
	}
	return layout.clauseBreaks[upper-1]
}

func (layout instructionLayout) clauseEnd(offset int) int {
	offset = min(max(offset, 0), len(layout.raw))
	next := sort.Search(len(layout.clauseBreaks), func(index int) bool {
		return layout.clauseBreaks[index] > offset
	})
	if next == len(layout.clauseBreaks) {
		return len(layout.raw)
	}
	return layout.clauseBreaks[next]
}

func (layout instructionLayout) spanRegion(start, end int) int {
	index := sort.Search(len(layout.regions), func(index int) bool { return layout.regions[index].end > start })
	if index < len(layout.regions) && start >= layout.regions[index].start && end <= layout.regions[index].end {
		return index
	}
	return -1
}

func (layout instructionLayout) candidateIsInert(candidate instructionCandidate) bool {
	region := layout.spanRegion(candidate.offset, candidate.offset+candidate.length)
	if region >= 0 && layout.regions[region].inert {
		return true
	}
	return layout.candidateIsInertInlineQuote(candidate)
}

func (layout instructionLayout) candidateIsInertInlineQuote(candidate instructionCandidate) bool {
	upper := sort.Search(len(layout.inlineInertStarts), func(index int) bool {
		return layout.inlineInertStarts[index] > candidate.offset
	})
	return upper > 0 && layout.inlineInertPrefixMaxEnds[upper-1] >= candidate.offset+candidate.length
}

func inlineDoubleQuoteSpans(line string) [][2]int {
	var spans [][2]int
	open := -1
	for index := 0; index < len(line); index++ {
		if line[index] != '"' || index > 0 && line[index-1] == '\\' {
			continue
		}
		if open < 0 {
			open = index + 1
		} else {
			spans = append(spans, [2]int{open, index})
			open = -1
		}
	}
	for searchFrom := 0; searchFrom < len(line); {
		openRelative := strings.Index(line[searchFrom:], "“")
		if openRelative < 0 {
			break
		}
		openStart := searchFrom + openRelative
		contentStart := openStart + len("“")
		closeRelative := strings.Index(line[contentStart:], "”")
		if closeRelative < 0 {
			break
		}
		closeStart := contentStart + closeRelative
		spans = append(spans, [2]int{contentStart, closeStart})
		searchFrom = closeStart + len("”")
	}
	return spans
}

func spanCandidateDistance(left, right instructionCandidate) int {
	return spanDistance([]int{left.offset, left.offset + left.length}, []int{right.offset, right.offset + right.length})
}

func (layout instructionLayout) candidatesRelated(left, right instructionCandidate) bool {
	if spanCandidateDistance(left, right) > instructionCompositionDistance {
		return false
	}
	leftPosition, rightPosition := layout.position(left.offset), layout.position(right.offset)
	if leftPosition.group != rightPosition.group || absInt(leftPosition.block-rightPosition.block) > 1 {
		return false
	}
	leftRegion := layout.spanRegion(left.offset, left.offset+left.length)
	rightRegion := layout.spanRegion(right.offset, right.offset+right.length)
	return leftRegion == rightRegion || leftRegion < 0 && rightRegion < 0
}

func (layout instructionLayout) directiveRelated(left, right []int) bool {
	leftCandidate := instructionCandidate{offset: left[0], length: left[1] - left[0]}
	rightCandidate := instructionCandidate{offset: right[0], length: right[1] - right[0]}
	if !layout.candidatesRelated(leftCandidate, rightCandidate) {
		return false
	}
	lp, rp := layout.position(left[0]), layout.position(right[0])
	if lp.block == rp.block {
		return true
	}
	return layout.adjacentBlocksLinked(lp.block, rp.block)
}

func (layout instructionLayout) adjacentBlocksLinked(leftIndex, rightIndex int) bool {
	if leftIndex < 0 || rightIndex < 0 || leftIndex >= len(layout.blocks) || rightIndex >= len(layout.blocks) || absInt(leftIndex-rightIndex) != 1 {
		return false
	}
	left, right := layout.blocks[leftIndex], layout.blocks[rightIndex]
	if left.group != right.group || left.region != right.region {
		return false
	}
	if left.kind == blockOrdered && right.kind == blockOrdered && left.orderedRun == right.orderedRun && absInt(left.orderedOrdinal-right.orderedOrdinal) == 1 {
		return true
	}
	earlier, later := left, right
	if leftIndex > rightIndex {
		earlier, later = right, left
	}
	laterText := layout.raw[later.start:later.end]
	if continuationPattern.MatchString(laterText) {
		return true
	}
	return shellVariableReference(layout.raw[earlier.start:earlier.end], laterText)
}

func shellVariableReference(assignment, use string) bool {
	match := shellVariableAssignmentPattern.FindStringSubmatch(assignment)
	if len(match) != 2 {
		return false
	}
	name := match[1]
	return strings.Contains(use, "$"+name) || strings.Contains(use, "${"+name+"}")
}

func (layout instructionLayout) directiveRelatedBlocks(block int) []int {
	if block < 0 || block >= len(layout.blocks) {
		return nil
	}
	related := []int{block}
	for _, candidate := range []int{block - 1, block + 1} {
		if candidate < 0 || candidate >= len(layout.blocks) {
			continue
		}
		if layout.adjacentBlocksLinked(block, candidate) {
			related = append(related, candidate)
		}
	}
	return related
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func semanticRuleCandidate(raw string, start, end int, kind instructionSemanticKind, ruleID, ruleName, label, severity string, strength sharedinstruction.Strength) instructionCandidate {
	return instructionCandidate{
		match: rules.Match{
			RuleID: ruleID, RuleName: ruleName, Severity: severity,
			Labels: []string{label}, Offset: start, Text: raw[start:end],
			Emit: rules.EmitConfig{FindingType: "has_injection_patterns", Labels: []string{label}},
		},
		kind: kind, label: label, strength: strength, specificity: candidateSpecificitySemantic,
		offset: start, length: end - start, evidenceOffset: start, evidenceLength: end - start,
	}
}

func semanticInstructionCandidates(ctx context.Context, raw string, layout instructionLayout) ([]instructionCandidate, error) {
	var candidates []instructionCandidate
	for _, spec := range []struct {
		pattern                       *regexp.Regexp
		kind                          instructionSemanticKind
		ruleID, name, label, severity string
		strength                      sharedinstruction.Strength
	}{
		{personaCuePattern, semanticPersonaCue, "instruction-persona-cue", "Agent Persona Cue", "persona_cue", "high", sharedinstruction.StrengthSupporting},
		{policyOverridePattern, semanticOverride, "instruction-policy-override", "Instruction Policy Override", "ignore_previous", "critical", sharedinstruction.StrengthPrimary},
		{controlBoundaryPattern, semanticControlBoundary, "instruction-control-boundary", "Instruction Control Boundary", "control_boundary", "critical", sharedinstruction.StrengthSupporting},
	} {
		locations, err := findPatternLocations(ctx, spec.pattern, raw)
		if err != nil {
			return nil, err
		}
		for _, location := range locations {
			candidates = append(candidates, semanticRuleCandidate(raw, location[0], location[1], spec.kind, spec.ruleID, spec.name, spec.label, spec.severity, spec.strength))
		}
	}
	actions, err := sensitiveActionCandidates(ctx, raw, layout)
	if err != nil {
		return nil, err
	}
	return append(candidates, actions...), nil
}

func findPatternLocations(ctx context.Context, pattern *regexp.Regexp, raw string) ([][]int, error) {
	var locations [][]int
	for offset, seen := 0, 0; offset <= len(raw); {
		if seen%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		location := pattern.FindStringIndex(raw[offset:])
		if location == nil {
			break
		}
		start, end := offset+location[0], offset+location[1]
		locations = append(locations, []int{start, end})
		seen++
		if end > offset {
			offset = end
		} else {
			offset++
		}
	}
	return locations, ctx.Err()
}

type semanticAction struct {
	location []int
	kind     string
}

func sensitiveActionCandidates(ctx context.Context, raw string, layout instructionLayout) ([]instructionCandidate, error) {
	var actions []semanticAction
	for _, spec := range []struct {
		pattern *regexp.Regexp
		kind    string
	}{{transferActionPattern, "transfer"}, {disclosureActionPattern, "disclosure"}, {outputActionPattern, "output"}} {
		locations, err := findPatternLocations(ctx, spec.pattern, raw)
		if err != nil {
			return nil, err
		}
		for _, location := range locations {
			actions = append(actions, semanticAction{location: location, kind: spec.kind})
		}
	}
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].location[0] != actions[j].location[0] {
			return actions[i].location[0] < actions[j].location[0]
		}
		return actions[i].kind < actions[j].kind
	})
	subjects, err := findPatternLocations(ctx, sensitiveMaterialPattern, raw)
	if err != nil {
		return nil, err
	}
	credentialIdentifiers, err := findPatternLocations(ctx, credentialIdentifierPattern, raw)
	if err != nil {
		return nil, err
	}
	subjects = append(subjects, credentialIdentifiers...)
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i][0] != subjects[j][0] {
			return subjects[i][0] < subjects[j][0]
		}
		return subjects[i][1] < subjects[j][1]
	})
	var candidates []instructionCandidate
	for actionIndex, action := range actions {
		if actionIndex%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if !validSensitiveAction(raw, action) {
			continue
		}
		first := sort.Search(len(subjects), func(index int) bool { return subjects[index][1] >= action.location[0]-instructionCompositionDistance })
		var best []int
		bestDistance := instructionCompositionDistance + 1
		for _, subject := range subjects[first:] {
			recordInstructionPairProbe()
			if subject[0] > action.location[1]+instructionCompositionDistance {
				break
			}
			distance := spanDistance(action.location, subject)
			if distance >= bestDistance || distance > instructionCompositionDistance || !sensitivePairRelated(raw, layout, action.location, subject) {
				continue
			}
			if !validSensitivePair(raw, action, subject, layout) {
				continue
			}
			best, bestDistance = subject, distance
		}
		if best == nil {
			continue
		}
		strength := sharedinstruction.StrengthSupporting
		if actionIsDirective(raw, action, best, layout) {
			strength = sharedinstruction.StrengthDecisive
		}
		start, end := min(action.location[0], best[0]), max(action.location[1], best[1])
		candidates = append(candidates, semanticRuleCandidate(raw, start, end, semanticSensitiveAction,
			"instruction-sensitive-action", "Sensitive Material Disclosure or Transfer", "sensitive_action", "critical", strength))
	}
	return candidates, nil
}

func sensitivePairRelated(raw string, layout instructionLayout, action, subject []int) bool {
	if !layout.directiveRelated(action, subject) {
		return false
	}
	actionPosition, subjectPosition := layout.position(action[0]), layout.position(subject[0])
	if actionPosition.block != subjectPosition.block {
		// Different blocks reach this point only through the layout's explicit
		// ordered-step, continuation, or one-hop variable links.
		return true
	}
	earlierEnd, laterStart := action[1], subject[0]
	if subject[1] <= action[0] {
		earlierEnd, laterStart = subject[1], action[0]
	}
	statementStart := layout.clauseStart(laterStart)
	if statementStart <= earlierEnd {
		return true
	}
	if continuationPattern.MatchString(raw[statementStart:laterStart]) {
		return true
	}
	laterStatement := raw[statementStart:min(layout.clauseEnd(laterStart), laterStart+instructionCompositionDistance)]
	if continuationPattern.MatchString(laterStatement) {
		return true
	}
	earlierStart := layout.clauseStart(max(0, earlierEnd-1))
	return shellVariableReference(raw[earlierStart:layout.clauseEnd(earlierEnd)], laterStatement)
}

func validSensitivePair(raw string, action semanticAction, subject []int, layout instructionLayout) bool {
	if actionIsProtected(raw, action.location, layout) || subjectIsProtected(raw, action.location, subject) || subjectIsRepresentational(raw, subject, layout) {
		return false
	}
	start, end := min(action.location[0], subject[0]), max(action.location[1], subject[1])
	windowStart, windowEnd := layout.relatedWindow(start, end)
	window := raw[windowStart:windowEnd]
	actionText := strings.ToLower(raw[action.location[0]:action.location[1]])
	switch action.kind {
	case "transfer":
		if actionText == "curl" || actionText == "wget" {
			if authMintPattern.MatchString(window) && authorizationPattern.MatchString(window) && !rawSecretSourcePattern.MatchString(window) {
				return false
			}
			if authorizationPattern.MatchString(window) {
				return rawSecretSourcePattern.MatchString(window)
			}
			return rawSecretSourcePattern.MatchString(window) || curlBodyCuePattern.MatchString(window) && destinationCuePattern.MatchString(window)
		}
		if strings.HasPrefix(actionText, "post") && !postPayloadCuePattern.MatchString(window) {
			return false
		}
		return destinationCuePattern.MatchString(window)
	case "output":
		if (strings.HasPrefix(actionText, "export") || strings.HasPrefix(actionText, "expos")) &&
			(subject[0] < action.location[1] || spanDistance(action.location, subject) > 96) {
			return false
		}
		return materialQualifierPattern.MatchString(window) || destinationCuePattern.MatchString(window)
	default:
		return true
	}
}

func actionIsDirective(raw string, action semanticAction, subject []int, layout instructionLayout) bool {
	position := layout.position(action.location[0])
	if position.block < 0 || position.block >= len(layout.blocks) {
		return false
	}
	block := layout.blocks[position.block]
	start := max(block.start, layout.clauseStart(action.location[0]), action.location[0]-instructionCompositionDistance)
	prefix := normalizeDirectivePrefix(raw[start:action.location[0]])
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" || imperativeLead(trimmed) {
		return true
	}
	if governedDirectivePattern.MatchString(prefix) || nestedDirectivePattern.MatchString(prefix) ||
		ensureDirectivePattern.MatchString(prefix) || orderedDirectivePattern.MatchString(prefix) ||
		colonDirectivePattern.MatchString(prefix) || sequencedDirectivePattern.MatchString(prefix) ||
		chainDirectivePattern.MatchString(prefix) || protectiveExceptionPattern.MatchString(prefix) {
		return true
	}
	if subject[1] <= action.location[0] {
		between := raw[subject[1]:action.location[0]]
		if passiveDirectivePattern.MatchString(between) {
			return true
		}
	}
	other := layout.position(subject[0])
	return position.kind == blockOrdered && other.kind == blockOrdered && position.orderedRun == other.orderedRun && absInt(position.orderedOrdinal-other.orderedOrdinal) == 1
}

func subjectIsProtected(raw string, action, subject []int) bool {
	if subject[0] <= action[1] {
		return false
	}
	between := raw[action[1]:subject[0]]
	return subjectProtectionPattern.MatchString(between)
}

func imperativeLead(prefix string) bool {
	lower := strings.ToLower(strings.TrimSpace(prefix))
	if (strings.HasPrefix(lower, "before ") || strings.HasPrefix(lower, "after ")) && strings.Contains(lower, ",") {
		lower = strings.TrimSpace(lower[strings.Index(lower, ",")+1:])
	}
	modifiers := []string{"please", "now", "then", "next", "also", "finally", "always", "immediately", "silently"}
	for consumed := 0; consumed < len(modifiers); consumed++ {
		changed := false
		for _, modifier := range modifiers {
			remainder, ok := consumeDirectiveModifier(lower, modifier)
			if !ok {
				continue
			}
			lower, changed = remainder, true
			break
		}
		if !changed {
			break
		}
	}
	if lower == "" {
		return true
	}
	if lower == "run" || lower == "execute" || lower == "invoke" || lower == "use" {
		return true
	}
	if (strings.HasPrefix(lower, "before ") || strings.HasPrefix(lower, "after ")) && strings.HasSuffix(lower, ",") {
		return true
	}
	return false
}

func consumeDirectiveModifier(value, modifier string) (string, bool) {
	if !strings.HasPrefix(value, modifier) {
		return value, false
	}
	remainder := value[len(modifier):]
	if remainder != "" && !strings.ContainsRune(" \t,;:", rune(remainder[0])) {
		return value, false
	}
	return strings.TrimSpace(strings.TrimLeft(remainder, ",;:")), true
}

func normalizeDirectivePrefix(prefix string) string {
	prefix = markdownMarkerPattern.ReplaceAllString(prefix, "")
	prefix = instructionTagPrefixPattern.ReplaceAllString(prefix, "")
	return prefix
}

func actionIsProtected(raw string, action []int, layout instructionLayout) bool {
	position := layout.position(action[0])
	start := max(layout.clauseStart(action[0]), action[0]-instructionCompositionDistance)
	if position.block >= 0 && position.block < len(layout.blocks) && layout.blocks[position.block].start > start {
		start = layout.blocks[position.block].start
	}
	prefix := raw[start:action[0]]
	if protectiveExceptionPattern.MatchString(prefix) {
		return false
	}
	return protectiveStartPattern.MatchString(prefix) || protectivePreventPattern.MatchString(prefix)
}

func subjectIsRepresentational(raw string, subject []int, layout instructionLayout) bool {
	position := layout.position(subject[0])
	blockStart, blockEnd := 0, len(raw)
	if position.block >= 0 && position.block < len(layout.blocks) {
		blockStart, blockEnd = layout.blocks[position.block].start, layout.blocks[position.block].end
	}
	prefix := raw[max(blockStart, subject[0]-48):subject[0]]
	if boundary := strings.LastIndexAny(prefix, ":;.!?\n"); boundary >= 0 {
		prefix = prefix[boundary+1:]
	}
	suffix := raw[subject[1]:min(blockEnd, subject[1]+56)]
	if representationPrefixPattern.MatchString(prefix) || representationSuffixPattern.MatchString(suffix) {
		return true
	}
	return noMaterialPrefixPattern.MatchString(prefix) && noMaterialSuffixPattern.MatchString(suffix)
}

func validSensitiveAction(raw string, action semanticAction) bool {
	start, end := action.location[0], action.location[1]
	actionText := strings.ToLower(raw[start:end])
	if (start > 0 && raw[start-1] == '-') || (end < len(raw) && raw[end] == '-') || start > 0 && raw[start-1] == '@' {
		return false
	}
	remainder := strings.TrimLeft(raw[end:min(len(raw), end+24)], " \t")
	if strings.HasPrefix(remainder, "(") {
		return false
	}
	if strings.HasPrefix(actionText, "export") {
		candidate := raw[start:min(len(raw), start+96)]
		if programmingExportPattern.MatchString(candidate) || shellExportAssignmentPattern.MatchString(candidate) {
			return false
		}
	}
	if strings.HasPrefix(actionText, "return") {
		lowerRemainder := strings.ToLower(remainder)
		if strings.HasPrefix(lowerRemainder, "new ") || strings.HasPrefix(lowerRemainder, "{") || strings.HasPrefix(lowerRemainder, "[") ||
			strings.HasPrefix(lowerRemainder, "\"") || strings.HasPrefix(lowerRemainder, "'") {
			return false
		}
	}
	return !strings.HasPrefix(actionText, "post") || !strings.HasPrefix(remainder, "/")
}

func spanDistance(left, right []int) int {
	if left[1] < right[0] {
		return right[0] - left[1]
	}
	if right[1] < left[0] {
		return left[0] - right[1]
	}
	return 0
}

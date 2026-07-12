package a2a

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

type DelegationEdge struct {
	SourceAgentID string
	TargetAgentID string
	Confidence    float64
	EvidenceState string
	MatchType     string
	MatchField    string
	MatchedRef    string
}

type AuthDomainEdge struct {
	AgentID1 string
	AgentID2 string
}

func AuthPostureScore(schemes []SecurityScheme) int {
	assessment := AuthAssessmentForSchemes(schemes, nil)
	if assessment.Weakness == nil {
		return -1
	}
	return int(*assessment.Weakness)
}

func DeriveAuthMethod(schemes []SecurityScheme, securityRefs []any) string {
	return string(AuthAssessmentForSchemes(schemes, securityRefs).Method)
}

func AuthAssessmentForSchemes(schemes []SecurityScheme, securityRefs []any) common.AuthAssessment {
	if len(schemes) == 0 {
		// A missing securitySchemes object is absence of assessment evidence,
		// not a declaration that the runtime accepts anonymous requests.
		return common.AssessAuth(string(common.AuthUnknown))
	}

	activeSchemes := schemes
	if len(securityRefs) > 0 {
		activeSchemes = resolveActiveSchemes(schemes, securityRefs)
	}
	if len(activeSchemes) == 0 {
		activeSchemes = schemes
	}

	var best *common.AuthAssessment
	for _, scheme := range activeSchemes {
		assessment := common.AssessAuth(string(authMethodForScheme(scheme)))
		if assessment.Weakness == nil {
			continue
		}
		if best == nil || *assessment.Weakness < *best.Weakness {
			copy := assessment
			best = &copy
		}
	}
	if best != nil {
		return *best
	}
	return common.AssessAuth(string(common.AuthUnknown))
}

func authMethodForScheme(scheme SecurityScheme) common.AuthMethod {
	switch strings.ToLower(strings.TrimSpace(scheme.Type)) {
	case "mutualtls":
		return common.AuthMTLS
	case "openidconnect":
		return common.AuthOIDC
	case "oauth2":
		return common.AuthOAuth
	case "apikey":
		return common.AuthAPIKey
	case "http":
		if method, ok := common.RecognizeAuthMethod(scheme.Scheme); ok {
			switch method {
			case common.AuthBasic, common.AuthBearer:
				return method
			}
		}
		return common.AuthUnknown
	default:
		return common.AuthUnknown
	}
}

func resolveActiveSchemes(schemes []SecurityScheme, securityRefs []any) []SecurityScheme {
	nameSet := make(map[string]bool)
	for _, ref := range securityRefs {
		switch v := ref.(type) {
		case map[string]any:
			for k := range v {
				nameSet[k] = true
			}
		case string:
			nameSet[v] = true
		}
	}

	var active []SecurityScheme
	for _, s := range schemes {
		if nameSet[s.Name] {
			active = append(active, s)
		}
	}
	return active
}

func DetectDelegation(cards []*AgentCardData) []DelegationEdge {
	type agentRef struct {
		id   string
		name string
		url  string
	}

	refs := make([]agentRef, len(cards))
	for i, c := range cards {
		refs[i] = agentRef{
			id:   agentNodeID(c),
			name: strings.ToLower(c.Name),
			url:  strings.ToLower(c.URL),
		}
	}

	var edges []DelegationEdge
	for i, src := range cards {
		for j, tgt := range refs {
			if i == j {
				continue
			}
			matchType, matchField, matchedRef, ok := delegationEvidence(src, tgt.name, tgt.url)
			if ok {
				edges = append(edges, DelegationEdge{
					SourceAgentID: refs[i].id,
					TargetAgentID: tgt.id,
					Confidence:    0.5,
					EvidenceState: "hypothesis",
					MatchType:     matchType,
					MatchField:    matchField,
					MatchedRef:    matchedRef,
				})
			}
		}
	}
	return edges
}

func delegationEvidence(
	card *AgentCardData,
	name, agentURL string,
) (matchType, matchField, matchedRef string, ok bool) {
	fields := []struct {
		name string
		text string
	}{{name: "agent.description", text: card.Description}}
	for _, skill := range card.Skills {
		fields = append(fields, struct {
			name string
			text string
		}{
			name: "skill.description:" + skill.ID,
			text: skill.Description,
		})
	}
	for _, field := range fields {
		text := strings.ToLower(field.text)
		if name != "" && len([]rune(name)) > 3 {
			if index := boundedReferenceIndex(text, name); index >= 0 &&
				hasDelegationCue(referenceSentence(text, index, len(name))) {
				return "lexical_name", field.name, name, true
			}
		}
		if agentURL != "" {
			if index := strings.Index(text, agentURL); index >= 0 &&
				hasDelegationCue(referenceSentence(text, index, len(agentURL))) {
				return "lexical_url", field.name, agentURL, true
			}
		}
	}
	return "", "", "", false
}

func boundedReferenceIndex(text, reference string) int {
	from := 0
	for from <= len(text) {
		relative := strings.Index(text[from:], reference)
		if relative < 0 {
			return -1
		}
		index := from + relative
		if hasTokenBoundaries(text, index, index+len(reference)) {
			return index
		}
		_, size := utf8.DecodeRuneInString(text[index:])
		if size == 0 {
			return -1
		}
		from = index + size
	}
	return -1
}

func referenceSentence(text string, index, length int) string {
	start := 0
	if boundary := strings.LastIndexAny(text[:index], ".!?\n;"); boundary >= 0 {
		start = boundary + 1
	}
	end := len(text)
	if boundary := strings.IndexAny(text[index+length:], ".!?\n;"); boundary >= 0 {
		end = index + length + boundary
	}
	return text[start:end]
}

var delegationCues = []string{
	"delegate", "delegates", "delegating",
	"route", "routes", "routing",
	"forward", "forwards", "forwarding",
	"hand off", "handoff",
	"invoke", "invokes", "invoking",
	"call", "calls", "calling",
	"send", "sends", "sending",
}

func hasDelegationCue(text string) bool {
	for _, cue := range delegationCues {
		index := boundedReferenceIndex(text, cue)
		if index < 0 {
			continue
		}
		prefixStart := max(0, index-24)
		prefix := text[prefixStart:index]
		negated := false
		for _, negation := range []string{"not", "never", "without", "cannot", "can't", "doesn't", "does not"} {
			if boundedReferenceIndex(prefix, negation) >= 0 {
				negated = true
				break
			}
		}
		if !negated {
			return true
		}
	}
	return false
}

func hasTokenBoundaries(text string, start, end int) bool {
	if start > 0 {
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		if before == '_' || unicode.IsLetter(before) || unicode.IsNumber(before) {
			return false
		}
	}
	if end < len(text) {
		after, _ := utf8.DecodeRuneInString(text[end:])
		if after == '_' || unicode.IsLetter(after) || unicode.IsNumber(after) {
			return false
		}
	}
	return true
}

func DetectSameAuthDomain(cards []*AgentCardData) []AuthDomainEdge {
	type domainInfo struct {
		agentID string
		domains []string
	}

	var agents []domainInfo
	for _, c := range cards {
		domains := extractOAuthDomains(c)
		if len(domains) > 0 {
			agents = append(agents, domainInfo{
				agentID: agentNodeID(c),
				domains: domains,
			})
		}
	}

	var edges []AuthDomainEdge
	for i := 0; i < len(agents); i++ {
		for j := i + 1; j < len(agents); j++ {
			if sharesDomain(agents[i].domains, agents[j].domains) {
				edges = append(edges, AuthDomainEdge{
					AgentID1: agents[i].agentID,
					AgentID2: agents[j].agentID,
				})
			}
		}
	}
	return edges
}

func extractOAuthDomains(card *AgentCardData) []string {
	var domains []string
	for _, s := range card.SecuritySchemes {
		if s.Type == "oauth2" || s.Type == "openIdConnect" {
			if d := extractDomain(card.URL); d != "" {
				domains = append(domains, d)
			}
		}
	}
	return domains
}

func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func sharesDomain(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, d := range a {
		set[d] = true
	}
	for _, d := range b {
		if set[d] {
			return true
		}
	}
	return false
}

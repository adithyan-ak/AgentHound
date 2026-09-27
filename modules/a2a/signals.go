package a2a

import (
	"net/url"
	"sort"
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

// Name-collision detection.
//
// A2A defines AgentCard.name as human-readable metadata with no uniqueness
// guarantee and no stable identifier. A collision becomes a security issue
// when a host promotes that remote-controlled name into an authority-bearing
// routing selector (registry key, agent-tree lookup, generated tool name,
// workflow node, client map key, or broker topic/queue): a peer advertising
// the same name can then receive tasks addressed to the trusted peer
// (CWE-706, "Agent Name Collision Attacks in Multi-Agent Systems").
//
// A network scanner cannot observe a target host's resolver from the
// outside, so this signal reports the observable precondition: two distinct
// admitted agents sharing one normalized name within the same collection
// scope. A hit is a fail-open routing surface, not proof of wrong-peer
// dispatch; score the concrete deployment path, not the abstract duplicate.

// NameCollisionMatchType distinguishes byte-identical names from names that
// collide only after normalization. Hosts that normalize names before
// routing (e.g. case-folding registries) are exposed by both.
type NameCollisionMatchType string

const (
	NameCollisionExact      NameCollisionMatchType = "exact"
	NameCollisionNormalized NameCollisionMatchType = "normalized"
)

// NameCollision is one pair of distinct agents whose cards advertise the
// same normalized name. AgentID1 sorts before AgentID2.
type NameCollision struct {
	AgentID1       string
	AgentID2       string
	NormalizedName string
	MatchType      NameCollisionMatchType
}

// NormalizeAgentName canonicalizes a card name for collision comparison.
// It mirrors the Cypher predicate (toLower(trim(a.name))) used by the
// prebuilt "a2a-agent-name-collision" query so both detectors agree.
func NormalizeAgentName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// DetectNameCollisions returns every pair of distinct agents whose cards
// advertise the same normalized name, ordered deterministically by agent
// ID. Cards without a name, and pairs resolving to the same agent node
// (the same card observed twice), are skipped.
func DetectNameCollisions(cards []*AgentCardData) []NameCollision {
	type namedAgent struct {
		id         string
		name       string
		normalized string
	}
	var agents []namedAgent
	seen := make(map[string]bool, len(cards))
	for _, c := range cards {
		if c == nil {
			continue
		}
		normalized := NormalizeAgentName(c.Name)
		if normalized == "" {
			continue
		}
		id := agentNodeID(c)
		if seen[id] {
			// The same agent observed twice must not multiply pairs.
			continue
		}
		seen[id] = true
		agents = append(agents, namedAgent{
			id:         id,
			name:       c.Name,
			normalized: normalized,
		})
	}

	var collisions []NameCollision
	for i := 0; i < len(agents); i++ {
		for j := i + 1; j < len(agents); j++ {
			if agents[i].id == agents[j].id {
				continue
			}
			if agents[i].normalized != agents[j].normalized {
				continue
			}
			first, second := agents[i].id, agents[j].id
			if first > second {
				first, second = second, first
			}
			matchType := NameCollisionNormalized
			if agents[i].name == agents[j].name {
				matchType = NameCollisionExact
			}
			collisions = append(collisions, NameCollision{
				AgentID1:       first,
				AgentID2:       second,
				NormalizedName: agents[i].normalized,
				MatchType:      matchType,
			})
		}
	}
	sort.Slice(collisions, func(a, b int) bool {
		if collisions[a].AgentID1 != collisions[b].AgentID1 {
			return collisions[a].AgentID1 < collisions[b].AgentID1
		}
		return collisions[a].AgentID2 < collisions[b].AgentID2
	})
	return collisions
}

func DeriveAuthMethod(
	schemes []SecurityScheme,
	requirements []SecurityRequirement,
) string {
	return string(AuthAssessmentForSchemes(schemes, requirements).Method)
}

func AuthAssessmentForSchemes(
	schemes []SecurityScheme,
	requirements []SecurityRequirement,
) common.AuthAssessment {
	if len(requirements) == 0 {
		// Scheme declarations are a catalog, not active runtime requirements.
		return common.AssessAuth(string(common.AuthUnknown))
	}

	byName := make(map[string]SecurityScheme, len(schemes))
	for _, scheme := range schemes {
		byName[scheme.Name] = scheme
	}
	var method common.AuthMethod
	for _, requirement := range requirements {
		if !requirement.Conformant {
			return common.AssessAuth(string(common.AuthUnknown))
		}
		var alternative common.AuthMethod
		switch len(requirement.Schemes) {
		case 0:
			alternative = common.AuthNone
		case 1:
			scheme, ok := byName[requirement.Schemes[0].Name]
			if !ok || !scheme.Conformant {
				return common.AssessAuth(string(common.AuthUnknown))
			}
			alternative = authMethodForScheme(scheme)
			if alternative == common.AuthUnknown {
				return common.AssessAuth(string(common.AuthUnknown))
			}
		default:
			// A scalar auth_method cannot represent an AND requirement.
			return common.AssessAuth(string(common.AuthUnknown))
		}
		if method == "" {
			method = alternative
		} else if method != alternative {
			// Distinct OR alternatives cannot be represented by one method.
			return common.AssessAuth(string(common.AuthUnknown))
		}
	}
	return common.AssessAuth(string(method))
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

func resolveActiveSchemes(
	schemes []SecurityScheme,
	requirements []SecurityRequirement,
) []SecurityScheme {
	nameSet := make(map[string]bool)
	for _, requirement := range requirements {
		if !requirement.Conformant {
			continue
		}
		for _, reference := range requirement.Schemes {
			nameSet[reference.Name] = true
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
		url := ""
		if c.PreferredURLValid {
			url = strings.ToLower(c.URL)
		}
		refs[i] = agentRef{
			id:   agentNodeID(c),
			name: strings.ToLower(c.Name),
			url:  url,
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
	var fields []struct {
		name string
		text string
	}
	if card.DescriptionValid || card.Description != "" {
		fields = append(fields, struct {
			name string
			text string
		}{name: "agent.description", text: card.Description})
	}
	for _, skill := range card.Skills {
		if !skill.Conformant {
			continue
		}
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
	if !card.PreferredURLValid {
		return nil
	}
	var domains []string
	for _, s := range resolveActiveSchemes(card.SecuritySchemes, card.SecurityRequirements) {
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

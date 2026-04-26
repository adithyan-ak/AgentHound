package a2a

import (
	"net/url"
	"strings"
)

type DelegationEdge struct {
	SourceAgentID string
	TargetAgentID string
	Confidence    float64
}

type AuthDomainEdge struct {
	AgentID1 string
	AgentID2 string
}

var authScores = map[string]int{
	"mutualTLS":     10,
	"openIdConnect": 20,
	"oauth2":        25,
	"http":          50,
	"apiKey":        70,
}

func AuthPostureScore(schemes []SecurityScheme) int {
	if len(schemes) == 0 {
		return 100
	}

	best := 100
	for _, s := range schemes {
		score, ok := authScores[s.Type]
		if !ok {
			continue
		}
		if score < best {
			best = score
		}
	}
	return best
}

func DeriveAuthMethod(schemes []SecurityScheme, securityRefs []any) string {
	if len(schemes) == 0 {
		return "none"
	}

	activeSchemes := schemes
	if len(securityRefs) > 0 {
		activeSchemes = resolveActiveSchemes(schemes, securityRefs)
	}
	if len(activeSchemes) == 0 {
		activeSchemes = schemes
	}

	priority := []struct {
		schemeType string
		method     string
	}{
		{"mutualTLS", "mtls"},
		{"openIdConnect", "oidc"},
		{"oauth2", "oauth"},
		{"http", "bearer"},
		{"apiKey", "apiKey"},
	}

	for _, p := range priority {
		for _, s := range activeSchemes {
			if s.Type == p.schemeType {
				return p.method
			}
		}
	}

	return "none"
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
		searchText := strings.ToLower(src.Description)
		for _, sk := range src.Skills {
			searchText += " " + strings.ToLower(sk.Description)
		}

		for j, tgt := range refs {
			if i == j {
				continue
			}
			if mentionsAgent(searchText, tgt.name, tgt.url) {
				edges = append(edges, DelegationEdge{
					SourceAgentID: refs[i].id,
					TargetAgentID: tgt.id,
					Confidence:    0.7,
				})
			}
		}
	}
	return edges
}

func mentionsAgent(text, name, agentURL string) bool {
	if name != "" && len(name) > 3 && strings.Contains(text, name) {
		return true
	}
	if agentURL != "" && strings.Contains(text, agentURL) {
		return true
	}
	return false
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

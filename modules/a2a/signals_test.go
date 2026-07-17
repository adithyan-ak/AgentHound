package a2a

import "testing"

func TestDeriveAuthMethod(t *testing.T) {
	tests := []struct {
		name         string
		schemes      []SecurityScheme
		requirements []SecurityRequirement
		want         string
	}{
		{"no schemes", nil, nil, "unknown"},
		{
			"declared only remains inactive",
			[]SecurityScheme{{Name: "ak", Type: "apiKey", Conformant: true}},
			nil,
			"unknown",
		},
		{
			"single active api key",
			[]SecurityScheme{{Name: "ak", Type: "apiKey", Conformant: true}},
			[]SecurityRequirement{{
				Conformant: true,
				Schemes:    []SecurityRequirementScheme{{Name: "ak"}},
			}},
			"apiKey",
		},
		{
			"and requirement cannot be scalar",
			[]SecurityScheme{
				{Name: "ak", Type: "apiKey", Conformant: true},
				{Name: "m", Type: "mutualTLS", Conformant: true},
			},
			[]SecurityRequirement{{
				Conformant: true,
				Schemes: []SecurityRequirementScheme{
					{Name: "ak"},
					{Name: "m"},
				},
			}},
			"unknown",
		},
		{
			"same method alternatives are unambiguous",
			[]SecurityScheme{
				{Name: "one", Type: "http", Scheme: "bearer", Conformant: true},
				{Name: "two", Type: "http", Scheme: "bearer", Conformant: true},
			},
			[]SecurityRequirement{
				{Conformant: true, Schemes: []SecurityRequirementScheme{{Name: "one"}}},
				{Conformant: true, Schemes: []SecurityRequirementScheme{{Name: "two"}}},
			},
			"bearer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveAuthMethod(tt.schemes, tt.requirements)
			if got != tt.want {
				t.Errorf("DeriveAuthMethod() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectDelegation(t *testing.T) {
	cards := []*AgentCardData{
		{
			Name:        "AgentA",
			Description: "I delegate tasks to agentb for processing",
			URL:         "https://a.example.com",
		},
		{
			Name:        "AgentB",
			Description: "I process data",
			URL:         "https://b.example.com",
		},
	}
	edges := DetectDelegation(cards)
	if len(edges) != 1 {
		t.Fatalf("expected 1 delegation edge, got %d", len(edges))
	}
	if edges[0].Confidence != 0.5 {
		t.Errorf("expected confidence 0.5, got %f", edges[0].Confidence)
	}
	if edges[0].EvidenceState != "hypothesis" ||
		edges[0].MatchType != "lexical_name" ||
		edges[0].MatchField != "agent.description" {
		t.Errorf("unexpected delegation provenance: %+v", edges[0])
	}
}

func TestDetectDelegation_NoMatch(t *testing.T) {
	cards := []*AgentCardData{
		{Name: "Alpha", Description: "Does stuff", URL: "https://alpha.example.com"},
		{Name: "Beta", Description: "Does other stuff", URL: "https://beta.example.com"},
	}
	edges := DetectDelegation(cards)
	if len(edges) != 0 {
		t.Errorf("expected 0 delegation edges, got %d", len(edges))
	}
}

func TestDetectDelegation_ByURL(t *testing.T) {
	cards := []*AgentCardData{
		{
			Name:        "Orchestrator",
			Description: "Routes work to https://worker.example.com for execution",
			URL:         "https://orch.example.com",
		},
		{
			Name:              "WorkerTarget",
			Description:       "Executes work",
			URL:               "https://worker.example.com",
			PreferredURLValid: true,
		},
	}
	edges := DetectDelegation(cards)
	if len(edges) != 1 {
		t.Fatalf("expected 1 delegation edge, got %d", len(edges))
	}
	if edges[0].MatchType != "lexical_url" {
		t.Fatalf("match type = %q, want lexical_url", edges[0].MatchType)
	}
}

func TestDetectDelegation_RequiresBoundaryAndDelegationContext(t *testing.T) {
	tests := []struct {
		name        string
		description string
		want        int
	}{
		{
			name:        "name substring is not an agent reference",
			description: "The betaagent compatibility matrix is documented here",
		},
		{
			name:        "plain documentation mention is not delegation",
			description: "AgentBeta is listed in the compatibility matrix",
		},
		{
			name:        "negated delegation remains benign",
			description: "This agent does not delegate to AgentBeta",
		},
		{
			name:        "contextual delegation is a hypothesis",
			description: "Route summarization tasks to AgentBeta",
			want:        1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edges := DetectDelegation([]*AgentCardData{
				{Name: "AgentAlpha", URL: "https://alpha.example.com", Description: tt.description},
				{Name: "AgentBeta", URL: "https://beta.example.com"},
			})
			if len(edges) != tt.want {
				t.Fatalf("DetectDelegation() = %+v, want %d edges", edges, tt.want)
			}
		})
	}
}

func TestDetectSameAuthDomain(t *testing.T) {
	cards := []*AgentCardData{
		{
			Name:                 "Agent1",
			URL:                  "https://api.example.com/a",
			PreferredURLValid:    true,
			SecuritySchemes:      []SecurityScheme{{Name: "oauth", Type: "oauth2", Conformant: true}},
			SecurityRequirements: []SecurityRequirement{{Conformant: true, Schemes: []SecurityRequirementScheme{{Name: "oauth"}}}},
		},
		{
			Name:                 "Agent2",
			URL:                  "https://api.example.com/b",
			PreferredURLValid:    true,
			SecuritySchemes:      []SecurityScheme{{Name: "oauth", Type: "oauth2", Conformant: true}},
			SecurityRequirements: []SecurityRequirement{{Conformant: true, Schemes: []SecurityRequirementScheme{{Name: "oauth"}}}},
		},
		{
			Name:                 "Agent3",
			URL:                  "https://other.example.com",
			PreferredURLValid:    true,
			SecuritySchemes:      []SecurityScheme{{Name: "oauth", Type: "oauth2", Conformant: true}},
			SecurityRequirements: []SecurityRequirement{{Conformant: true, Schemes: []SecurityRequirementScheme{{Name: "oauth"}}}},
		},
	}
	edges := DetectSameAuthDomain(cards)
	if len(edges) != 1 {
		t.Fatalf("expected 1 same-auth-domain edge, got %d", len(edges))
	}
}

func TestDetectSameAuthDomain_NoOAuth(t *testing.T) {
	cards := []*AgentCardData{
		{
			Name:                 "Agent1",
			URL:                  "https://a.example.com",
			SecuritySchemes:      []SecurityScheme{{Name: "ak", Type: "apiKey", Conformant: true}},
			SecurityRequirements: []SecurityRequirement{{Conformant: true, Schemes: []SecurityRequirementScheme{{Name: "ak"}}}},
		},
		{
			Name:                 "Agent2",
			URL:                  "https://a.example.com",
			SecuritySchemes:      []SecurityScheme{{Name: "ak", Type: "apiKey", Conformant: true}},
			SecurityRequirements: []SecurityRequirement{{Conformant: true, Schemes: []SecurityRequirementScheme{{Name: "ak"}}}},
		},
	}
	edges := DetectSameAuthDomain(cards)
	if len(edges) != 0 {
		t.Errorf("expected 0 edges for apiKey-only agents, got %d", len(edges))
	}
}

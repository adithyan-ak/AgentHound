package handlers

import (
	"net/http"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/go-chi/chi/v5"
)

type RulesHandler struct {
	engine *rules.Engine
}

func NewRulesHandler(engine *rules.Engine) *RulesHandler {
	return &RulesHandler{engine: engine}
}

type RuleResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     int      `json:"version"`
	Enabled     bool     `json:"enabled"`
	Severity    string   `json:"severity"`
	Collector   string   `json:"collector"`
	Targets     []string `json:"targets"`
	MatcherType string   `json:"matcher_type"`
	OWASP       []string `json:"owasp,omitempty"`
	Tags        []string `json:"tags"`
	Source      string   `json:"source"`
	TestCount   int      `json:"test_count"`
}

type RuleDetailResponse struct {
	RuleResponse
	Matcher rules.MatcherSpec `json:"matcher"`
	Tests   []rules.TestCase  `json:"tests"`
}

func ruleToResponse(r rules.Rule) RuleResponse {
	tags := r.Tags
	if tags == nil {
		tags = []string{}
	}
	targets := r.Scope.Targets
	if targets == nil {
		targets = []string{}
	}
	return RuleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Version:     r.Version,
		Enabled:     true,
		Severity:    r.Severity,
		Collector:   r.Scope.Collector,
		Targets:     targets,
		MatcherType: r.Matcher.Type,
		OWASP:       r.OWASP,
		Tags:        tags,
		Source:      r.Source,
		TestCount:   len(r.Tests),
	}
}

func (h *RulesHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		WriteJSON(w, http.StatusOK, map[string]any{
			"rules": []RuleResponse{},
			"total": 0,
		})
		return
	}

	collector := r.URL.Query().Get("collector")
	severity := r.URL.Query().Get("severity")
	tag := r.URL.Query().Get("tag")

	all := h.engine.Rules()
	var filtered []RuleResponse
	for _, rule := range all {
		if collector != "" && !strings.EqualFold(rule.Scope.Collector, collector) {
			continue
		}
		if severity != "" && !strings.EqualFold(rule.Severity, severity) {
			continue
		}
		if tag != "" && !hasTag(rule.Tags, tag) {
			continue
		}
		filtered = append(filtered, ruleToResponse(rule))
	}
	if filtered == nil {
		filtered = []RuleResponse{}
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"rules": filtered,
		"total": len(filtered),
	})
}

func (h *RulesHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		WriteNotFound(w, "rule not found")
		return
	}

	id := chi.URLParam(r, "id")
	for _, rule := range h.engine.Rules() {
		if rule.ID == id {
			tests := rule.Tests
			if tests == nil {
				tests = []rules.TestCase{}
			}
			WriteJSON(w, http.StatusOK, RuleDetailResponse{
				RuleResponse: ruleToResponse(rule),
				Matcher:      rule.Matcher,
				Tests:        tests,
			})
			return
		}
	}

	WriteNotFound(w, "rule not found")
}

func hasTag(tags []string, target string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, target) {
			return true
		}
	}
	return false
}

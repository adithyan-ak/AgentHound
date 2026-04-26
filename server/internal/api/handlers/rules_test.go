package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/rules"
	"github.com/go-chi/chi/v5"
)

func testRulesEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestRulesHandler_HandleList(t *testing.T) {
	engine := testRulesEngine(t)
	h := NewRulesHandler(engine)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules", nil)
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Rules []RuleResponse `json:"rules"`
		Total int            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total == 0 {
		t.Fatal("expected at least 1 rule, got 0")
	}
	if resp.Total != len(resp.Rules) {
		t.Fatalf("total %d != len(rules) %d", resp.Total, len(resp.Rules))
	}

	first := resp.Rules[0]
	if first.ID == "" {
		t.Fatal("rule ID is empty")
	}
	if first.Severity == "" {
		t.Fatal("rule severity is empty")
	}
	if first.MatcherType == "" {
		t.Fatal("rule matcher_type is empty")
	}
}

func TestRulesHandler_HandleList_FilterBySeverity(t *testing.T) {
	engine := testRulesEngine(t)
	h := NewRulesHandler(engine)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules?severity=critical", nil)
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Rules []RuleResponse `json:"rules"`
		Total int            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	for _, rule := range resp.Rules {
		if rule.Severity != "critical" {
			t.Fatalf("expected severity critical, got %s for rule %s", rule.Severity, rule.ID)
		}
	}
}

func TestRulesHandler_HandleList_FilterByCollector(t *testing.T) {
	engine := testRulesEngine(t)
	h := NewRulesHandler(engine)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules?collector=mcp", nil)
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Rules []RuleResponse `json:"rules"`
		Total int            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total == 0 {
		t.Fatal("expected at least 1 mcp rule")
	}
	for _, rule := range resp.Rules {
		if rule.Collector != "mcp" {
			t.Fatalf("expected collector mcp, got %s for rule %s", rule.Collector, rule.ID)
		}
	}
}

func TestRulesHandler_HandleList_FilterByTag(t *testing.T) {
	engine := testRulesEngine(t)
	h := NewRulesHandler(engine)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules?tag=injection", nil)
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Rules []RuleResponse `json:"rules"`
		Total int            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	for _, rule := range resp.Rules {
		found := false
		for _, tag := range rule.Tags {
			if tag == "injection" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("rule %s missing injection tag, has %v", rule.ID, rule.Tags)
		}
	}
}

func TestRulesHandler_HandleList_NoResults(t *testing.T) {
	engine := testRulesEngine(t)
	h := NewRulesHandler(engine)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules?severity=nonexistent", nil)
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Rules []RuleResponse `json:"rules"`
		Total int            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 0 {
		t.Fatalf("expected 0 rules, got %d", resp.Total)
	}
	if len(resp.Rules) != 0 {
		t.Fatalf("expected empty rules array, got %d", len(resp.Rules))
	}
}

func TestRulesHandler_HandleGet(t *testing.T) {
	engine := testRulesEngine(t)
	h := NewRulesHandler(engine)

	allRules := engine.Rules()
	if len(allRules) == 0 {
		t.Fatal("no builtin rules loaded")
	}
	targetID := allRules[0].ID

	router := chi.NewRouter()
	router.Get("/api/v1/rules/{id}", h.HandleGet)

	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules/"+targetID, nil)
	router.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp RuleDetailResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != targetID {
		t.Fatalf("expected id %s, got %s", targetID, resp.ID)
	}
	if resp.Matcher.Type == "" {
		t.Fatal("matcher type is empty in detail response")
	}
}

func TestRulesHandler_HandleGet_NotFound(t *testing.T) {
	engine := testRulesEngine(t)
	h := NewRulesHandler(engine)

	router := chi.NewRouter()
	router.Get("/api/v1/rules/{id}", h.HandleGet)

	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules/nonexistent-rule-id", nil)
	router.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Fatalf("expected NOT_FOUND, got %s", resp.Error.Code)
	}
}

func TestRulesHandler_HandleList_NilEngine(t *testing.T) {
	h := NewRulesHandler(nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules", nil)
	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Rules []RuleResponse `json:"rules"`
		Total int            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 0 {
		t.Fatalf("expected 0 rules with nil engine, got %d", resp.Total)
	}
	if len(resp.Rules) != 0 {
		t.Fatalf("expected empty rules array, got %d", len(resp.Rules))
	}
}

func TestRulesHandler_HandleGet_NilEngine(t *testing.T) {
	h := NewRulesHandler(nil)

	router := chi.NewRouter()
	router.Get("/api/v1/rules/{id}", h.HandleGet)

	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/rules/anything", nil)
	router.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

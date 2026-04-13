package cli

import (
	"testing"

	"github.com/adithyan-ak/agenthound/internal/analysis"
	"github.com/adithyan-ak/agenthound/internal/model"
)

func TestCountFindingsBySeverity(t *testing.T) {
	findings := []analysis.Finding{
		{ID: "1", Severity: "critical"},
		{ID: "2", Severity: "high"},
		{ID: "3", Severity: "high"},
		{ID: "4", Severity: "medium"},
		{ID: "5", Severity: "low"},
		{ID: "6", Severity: "low"},
		{ID: "7", Severity: "low"},
	}
	counts := countFindingsBySeverity(findings)

	want := map[string]int{"critical": 1, "high": 2, "medium": 1, "low": 3}
	for sev, expected := range want {
		if counts[sev] != expected {
			t.Errorf("severity %q: got %d, want %d", sev, counts[sev], expected)
		}
	}
}

func TestCountFindingsBySeverity_Empty(t *testing.T) {
	counts := countFindingsBySeverity(nil)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if counts[sev] != 0 {
			t.Errorf("severity %q: got %d, want 0", sev, counts[sev])
		}
	}
}

func TestCountAtOrAbove(t *testing.T) {
	findings := []analysis.Finding{
		{ID: "1", Severity: "critical"},
		{ID: "2", Severity: "high"},
		{ID: "3", Severity: "high"},
		{ID: "4", Severity: "medium"},
		{ID: "5", Severity: "low"},
	}
	got := countAtOrAbove(findings, severityRank["high"])
	if got != 3 {
		t.Errorf("countAtOrAbove(threshold=high): got %d, want 3", got)
	}
}

func TestCountAtOrAbove_NoneAbove(t *testing.T) {
	findings := []analysis.Finding{
		{ID: "1", Severity: "medium"},
		{ID: "2", Severity: "medium"},
		{ID: "3", Severity: "low"},
	}
	got := countAtOrAbove(findings, severityRank["critical"])
	if got != 0 {
		t.Errorf("countAtOrAbove(threshold=critical): got %d, want 0", got)
	}
}

func TestCollectorDetail_Config(t *testing.T) {
	data := &model.IngestData{
		Graph: model.GraphData{
			Nodes: []model.Node{
				{ID: "1", Kinds: []string{"AgentInstance"}},
				{ID: "2", Kinds: []string{"AgentInstance"}},
				{ID: "3", Kinds: []string{"MCPServer"}},
				{ID: "4", Kinds: []string{"Credential"}},
				{ID: "5", Kinds: []string{"Credential"}},
				{ID: "6", Kinds: []string{"Credential"}},
			},
		},
	}
	got := collectorDetail(data, "config")
	want := "2 agents, 1 servers, 3 credentials"
	if got != want {
		t.Errorf("collectorDetail(config): got %q, want %q", got, want)
	}
}

func TestCollectorDetail_MCP(t *testing.T) {
	data := &model.IngestData{
		Graph: model.GraphData{
			Nodes: []model.Node{
				{ID: "1", Kinds: []string{"MCPTool"}},
				{ID: "2", Kinds: []string{"MCPTool"}},
				{ID: "3", Kinds: []string{"MCPResource"}},
				{ID: "4", Kinds: []string{"MCPPrompt"}},
			},
		},
	}
	got := collectorDetail(data, "mcp")
	want := "2 tools, 1 resources, 1 prompts"
	if got != want {
		t.Errorf("collectorDetail(mcp): got %q, want %q", got, want)
	}
}

func TestCollectorDetail_A2A(t *testing.T) {
	data := &model.IngestData{
		Graph: model.GraphData{
			Nodes: []model.Node{
				{ID: "1", Kinds: []string{"A2AAgent"}},
				{ID: "2", Kinds: []string{"A2ASkill"}},
				{ID: "3", Kinds: []string{"A2ASkill"}},
				{ID: "4", Kinds: []string{"A2ASkill"}},
			},
		},
	}
	got := collectorDetail(data, "a2a")
	want := "1 agents, 3 skills"
	if got != want {
		t.Errorf("collectorDetail(a2a): got %q, want %q", got, want)
	}
}

func TestOrderResults(t *testing.T) {
	results := []scanResult{
		{name: "A2A", status: "ok"},
		{name: "MCP", status: "ok"},
		{name: "Config", status: "ok"},
	}
	ordered := orderResults(results)

	wantOrder := []string{"Config", "MCP", "A2A"}
	for i, want := range wantOrder {
		if ordered[i].name != want {
			t.Errorf("position %d: got %q, want %q", i, ordered[i].name, want)
		}
	}

	if results[0].name != "A2A" {
		t.Error("orderResults mutated the original slice")
	}
}

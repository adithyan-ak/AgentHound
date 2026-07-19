package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

func sharedVSCodeSettingsPath(t *testing.T, home string) string {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json")
	case "linux":
		return filepath.Join(home, ".config", "Code", "User", "settings.json")
	default:
		t.Skip("shared VS Code settings path is not registered on this OS")
		return ""
	}
}

func TestSharedDiscoveryMultiClientPhysicalFile(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	settings := sharedVSCodeSettingsPath(t, home)
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{
  "mcp.servers": {"vscode-server": {"command": "vscode-mcp"}},
  "augment.advanced": {"mcpServers": [{"name": "augment-server", "command": "augment-mcp"}]}
}`
	if err := os.WriteFile(settings, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := NewConfigCollector().Collect(context.Background(), collector.CollectOptions{
		Discover: true, ProjectDir: project, ScanID: "multi-client",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var files []ingest.Node
	var agents []string
	for _, node := range result.Graph.Nodes {
		if hasNodeKind(node, "ConfigFile") && node.Properties["path"] == settings {
			files = append(files, node)
		}
		if hasNodeKind(node, "AgentInstance") && node.Properties["config_path"] == settings {
			framework, ok := node.Properties["framework"].(string)
			if !ok {
				t.Fatalf("AgentInstance framework = %#v, want string", node.Properties["framework"])
			}
			agents = append(agents, framework)
		}
	}
	if len(files) != 1 {
		t.Fatalf("ConfigFile count for shared path = %d, want 1", len(files))
	}
	clients, ok := files[0].Properties["clients"].([]string)
	if !ok || !reflect.DeepEqual(clients, []string{"augment", "vscode"}) {
		t.Fatalf("clients = %#v, want [augment vscode]", files[0].Properties["clients"])
	}
	if _, singular := files[0].Properties["client"]; singular {
		t.Fatal("multi-client ConfigFile must not emit singular client")
	}
	if files[0].Properties["server_count"] != 2 {
		t.Fatalf("server_count = %v, want 2", files[0].Properties["server_count"])
	}
	sort.Strings(agents)
	if !reflect.DeepEqual(agents, []string{"augment", "vscode"}) {
		t.Fatalf("agents = %v, want [augment vscode]", agents)
	}
	physicalOutcomes := 0
	for _, outcome := range result.Meta.Collection.Outcomes {
		if outcome.Target == settings && outcome.Method == "config_discovery" {
			physicalOutcomes++
			if outcome.State != ingest.OutcomeComplete || outcome.Items != 1 {
				t.Fatalf("shared file outcome = %+v", outcome)
			}
		}
	}
	if physicalOutcomes != 1 {
		t.Fatalf("physical outcomes = %d, want 1", physicalOutcomes)
	}
}

func TestSharedDiscoveryApplicabilityStates(t *testing.T) {
	parsers := []ConfigParser{&AugmentParser{}, &VSCodeParser{}}
	path := filepath.Join(t.TempDir(), "settings.json")
	tests := []struct {
		name, content string
		state         ingest.OutcomeState
		items, views  int
	}{
		{"recognized empty", `{"mcp.servers":{}}`, ingest.OutcomeComplete, 1, 1},
		{"inapplicable", `{"editor.fontSize":14}`, ingest.OutcomeComplete, 0, 0},
		{"valid plus malformed", `{"mcp.servers":{"ok":{"command":"mcp"}},"augment.advanced":"bad"}`, ingest.OutcomePartial, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got := discoverPhysicalFile(path, parsers, nil)
			if got.State != tt.state || got.Items != tt.items || len(got.Configs) != tt.views {
				t.Fatalf("discovery = state:%s items:%d views:%d error:%q", got.State, got.Items, len(got.Configs), got.Error)
			}
		})
	}
}

func TestSharedDiscoveryRetainsValidEntriesButMarksMalformedSiblingPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(`{
  "mcpServers": {
    "valid": {"command": "real-mcp", "args": ["--serve"]},
    "malformed": 42
  }
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	discovery := discoverPhysicalFile(path, []ConfigParser{&CursorParser{}}, nil)
	if discovery.State != ingest.OutcomePartial || discovery.Items != 1 || len(discovery.Configs) != 1 {
		t.Fatalf("mixed-entry discovery = %+v, want one retained partial view", discovery)
	}
	servers := discovery.Configs[0].Servers
	if len(servers) != 1 || servers[0].Name != "valid" || servers[0].Command != "real-mcp" {
		t.Fatalf("retained servers = %+v, want only the valid real entry", servers)
	}
}

func TestExplicitConfigRunsAllParsersWithoutInventingAClient(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	projectRoot, err := ResolveProjectRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = projectRoot.Close() }()
	path := filepath.Join(t.TempDir(), "exported-config.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"real":{"command":"real-mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	discovery := NewConfigCollector().DiscoverConfigs(context.Background(), home, projectRoot, false, []string{path})
	if len(discovery.Files) != 1 || len(discovery.Files[0].Configs) != 1 {
		t.Fatalf("explicit discovery = %+v", discovery.Files)
	}
	if got := discovery.Files[0].Configs[0].Client; got != "unknown" {
		t.Fatalf("ambiguous exported client = %q, want honest unknown", got)
	}
	if len(discovery.Files[0].Configs[0].Servers) != 1 {
		t.Fatalf("servers = %+v", discovery.Files[0].Configs[0].Servers)
	}

	known := filepath.Join(project, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(known), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(known, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	discovery = NewConfigCollector().DiscoverConfigs(context.Background(), home, projectRoot, false, []string{known})
	if len(discovery.Files[0].Configs) != 1 || discovery.Files[0].Configs[0].Client != "cursor" {
		t.Fatalf("known path ownership = %+v, want cursor", discovery.Files[0].Configs)
	}
}

func TestConfigDiscoveryBoundsAndMissingState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	got := discoverPhysicalFile(missing, []ConfigParser{&CursorParser{}}, nil)
	if got.State != ingest.OutcomeComplete || got.Items != 0 || len(got.Configs) != 0 {
		t.Fatalf("missing file = %+v, want complete empty", got)
	}

	oversized := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat(" ", int(maxConfigFileBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	got = discoverPhysicalFile(oversized, []ConfigParser{&CursorParser{}}, nil)
	if got.State != ingest.OutcomeTruncated || got.Items != 0 {
		t.Fatalf("oversized file = %+v, want truncated", got)
	}
}

func TestDiscoverNestedCursorRulesPrunesGitBeforeBudget(t *testing.T) {
	project := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(project, ".cursor", "rules", "root.mdc"), "root rule")
	write(filepath.Join(project, ".cursor", "rules", ".git", "ignored.mdc"), "ignored")
	write(filepath.Join(project, "component", ".cursor", "rules", "nested.mdc"), "nested rule")
	for i := 0; i < 20; i++ {
		write(filepath.Join(project, ".git", "objects", string(rune('a'+i)), "ignored.mdc"), "ignored")
	}

	oldLimit := instructionTraversalEntryLimit
	instructionTraversalEntryLimit = 8
	t.Cleanup(func() { instructionTraversalEntryLimit = oldLimit })
	engine, err := rules.NewEngine(rules.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	discovery := DiscoverInstructions(context.Background(), "", project, engine)
	var cursorPaths []string
	for _, observation := range discovery.Observations {
		if observation.Info.Type == "cursor-rule" {
			cursorPaths = append(cursorPaths, observation.Info.Path)
			if strings.Contains(observation.Info.Path, string(filepath.Separator)+".git"+string(filepath.Separator)) {
				t.Fatalf("collected rule from .git: %s", observation.Info.Path)
			}
			if strings.Contains(observation.OwnerKey, ":instruction-file:") {
				t.Fatalf("cursor rule received additive file ownership: %s", observation.OwnerKey)
			}
		}
	}
	sort.Strings(cursorPaths)
	if len(cursorPaths) != 2 {
		t.Fatalf("cursor rules = %v, want root and nested", cursorPaths)
	}
	for _, outcome := range discovery.Outcomes {
		if outcome.Method == "cursor_rule_traversal" || outcome.Method == "cursor_rule_tree" {
			if outcome.State != ingest.OutcomeComplete {
				t.Fatalf(".git consumed traversal budget: %+v", outcome)
			}
		}
	}
}

func TestCursorRuleTreeIncompleteStates(t *testing.T) {
	project := t.TempDir()
	rule := filepath.Join(project, ".cursor", "rules", "oversized.mdc")
	if err := os.MkdirAll(filepath.Dir(rule), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule, []byte(strings.Repeat("x", int(maxInstructionFileBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.NewEngine(rules.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	discovery := DiscoverInstructions(context.Background(), "", project, engine)
	states := make(map[string]ingest.OutcomeState)
	for _, outcome := range discovery.Outcomes {
		states[outcome.Method] = outcome.State
	}
	if states["cursor_rule_read"] != ingest.OutcomeTruncated ||
		states["cursor_rule_tree"] != ingest.OutcomeTruncated ||
		states["cursor_rule_traversal"] != ingest.OutcomeTruncated {
		t.Fatalf("oversized cursor states = %v", states)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	discovery = DiscoverInstructions(canceled, "", project, engine)
	for _, outcome := range discovery.Outcomes {
		if outcome.Method == "cursor_rule_traversal" && outcome.State != ingest.OutcomePartial {
			t.Fatalf("canceled traversal = %+v", outcome)
		}
	}

	unreadable := filepath.Join(project, ".cursor", "rules", "unreadable.mdc")
	if err := os.WriteFile(unreadable, []byte("real rule"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalOpen := openConfigFile
	openConfigFile = func(path string) (*os.File, error) {
		if canonicalConfigPath(path) == canonicalConfigPath(unreadable) {
			return nil, os.ErrPermission
		}
		return os.Open(path)
	}
	t.Cleanup(func() { openConfigFile = originalOpen })
	discovery = DiscoverInstructions(context.Background(), "", project, engine)
	for _, outcome := range discovery.Outcomes {
		if outcome.Target == canonicalConfigPath(unreadable) && outcome.State != ingest.OutcomeFailed {
			t.Fatalf("unreadable file outcome = %+v", outcome)
		}
		if outcome.Method == "cursor_rule_tree" && outcome.State == ingest.OutcomeComplete {
			t.Fatalf("unreadable tree became complete: %+v", outcome)
		}
	}
}

func TestCursorLifecycleScopeSemantics(t *testing.T) {
	root := ingest.CollectorRootCoverageKey("config")
	traversal := instructionTraversalKey("/project")
	tree := instructionTreeKey("/project/.cursor/rules")
	file := instructionFileKey("/project/.cursor/rules/deleted.mdc")

	report := func(rootState, traversalState, treeState ingest.OutcomeState, includeTree bool, active []string) *ingest.CollectionReport {
		coverageKeys := []string{root, traversal}
		outcomes := []ingest.CollectionOutcome{
			{Collector: "config", CoverageKey: root, State: rootState},
			{Collector: "config", CoverageKey: traversal, State: traversalState},
		}
		if includeTree {
			coverageKeys = append(coverageKeys, tree)
			outcomes = append(outcomes, ingest.CollectionOutcome{Collector: "config", CoverageKey: tree, State: treeState})
		}
		return &ingest.CollectionReport{
			State:              ingest.AggregateOutcomeState(outcomes),
			CoverageKeys:       coverageKeys,
			Outcomes:           outcomes,
			AuthoritativeRoots: []ingest.CoverageRoot{{CoverageKey: root, ChildCoverageKeys: active}},
		}
	}

	t.Run("complete tree retires deleted file despite unrelated traversal failure", func(t *testing.T) {
		got := report(ingest.OutcomePartial, ingest.OutcomePartial, ingest.OutcomeComplete, true, []string{traversal, tree})
		if !containsString(ingest.CompleteCoverageDomains(got), tree) {
			t.Fatalf("complete domains = %v, want tree %s", ingest.CompleteCoverageDomains(got), tree)
		}
		if containsString(ingest.CompleteCoverageDomains(got), file) {
			t.Fatalf("diagnostic file key unexpectedly declared complete: %s", file)
		}
		if len(ingest.CompleteAuthoritativeRoots(got)) != 0 {
			t.Fatal("partial traversal completed authoritative root")
		}
	})

	t.Run("partial tree retains missing file", func(t *testing.T) {
		got := report(ingest.OutcomePartial, ingest.OutcomePartial, ingest.OutcomePartial, true, []string{traversal, tree})
		if containsString(ingest.CompleteCoverageDomains(got), tree) {
			t.Fatal("partial tree became a reconciliation domain")
		}
	})

	t.Run("partial traversal retains absent tree", func(t *testing.T) {
		got := report(ingest.OutcomePartial, ingest.OutcomePartial, ingest.OutcomeComplete, false, []string{traversal})
		if len(ingest.CompleteAuthoritativeRoots(got)) != 0 {
			t.Fatal("partial traversal retired an absent tree")
		}
	})

	t.Run("complete traversal root retires absent tree", func(t *testing.T) {
		got := report(ingest.OutcomeComplete, ingest.OutcomeComplete, ingest.OutcomeComplete, false, []string{traversal})
		roots := ingest.CompleteAuthoritativeRoots(got)
		if len(roots) != 1 || containsString(roots[0].ChildCoverageKeys, tree) {
			t.Fatalf("completed roots = %+v, want active set without old tree", roots)
		}
	})
}

func TestResolveProjectRootRejectsInvalidPaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := ResolveProjectRoot(missing); err == nil {
		t.Fatal("missing project root accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProjectRoot(file); err == nil {
		t.Fatal("non-directory project root accepted")
	}
}

func TestConfigDiscoveryRetainsResultsWhenProjectRootDisappearsAfterValidation(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	globalConfig := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(globalConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalConfig, []byte(`{"mcpServers":{"retained":{"command":"retained-mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	projectRoot, err := ResolveProjectRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = projectRoot.Close() }()
	if err := os.RemoveAll(project); err != nil {
		t.Fatal(err)
	}

	discovery := NewConfigCollector().DiscoverConfigs(context.Background(), home, projectRoot, true, nil)
	if discovery.ProjectRootState != ingest.OutcomeFailed || discovery.ProjectRootError == "" {
		t.Fatalf("project root result = state:%s error:%q, want failed boundary", discovery.ProjectRootState, discovery.ProjectRootError)
	}
	configs := discovery.ParsedConfigs()
	if len(configs) != 1 || len(configs[0].Servers) != 1 || configs[0].Servers[0].Name != "retained" {
		t.Fatalf("retained global config = %+v", configs)
	}
}

func TestExplicitProjectRootOverridesWorkingDirectory(t *testing.T) {
	home, projectA, projectB := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	configPath := filepath.Join(projectB, ".vscode", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"servers":{"from-b":{"command":"project-b-mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectA); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	result, err := NewConfigCollector().Collect(context.Background(), collector.CollectOptions{
		Discover: true, ProjectDir: projectB, ScanID: "project-root",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	foundB := false
	for _, node := range result.Graph.Nodes {
		if hasNodeKind(node, "ConfigFile") && node.Properties["path"] == configPath {
			foundB = true
		}
		if path, _ := node.Properties["config_path"].(string); path != "" && strings.HasPrefix(path, projectA) {
			t.Fatalf("collected config from CWD A: %s", path)
		}
	}
	if !foundB {
		t.Fatalf("explicit project B config %s was not collected", configPath)
	}
}

func TestResolveProjectRootInjectedFailures(t *testing.T) {
	originalGetwd, originalOpen := getWorkingDirectory, openProjectRoot
	t.Cleanup(func() {
		getWorkingDirectory, openProjectRoot = originalGetwd, originalOpen
	})
	getWorkingDirectory = func() (string, error) { return "", errors.New("cwd unavailable") }
	if _, err := ResolveProjectRoot(""); err == nil {
		t.Fatal("failed CWD resolution was accepted")
	}
	getWorkingDirectory = originalGetwd
	openProjectRoot = func(string) (*os.File, error) { return nil, os.ErrPermission }
	if _, err := ResolveProjectRoot(t.TempDir()); err == nil {
		t.Fatal("inaccessible project root was accepted")
	}
}

func hasNodeKind(node ingest.Node, kind string) bool {
	for _, candidate := range node.Kinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

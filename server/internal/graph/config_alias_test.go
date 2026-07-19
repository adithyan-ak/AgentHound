package graph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	configmodule "github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/sdk/collector"
)

func TestWriterPreparationAcceptsCollapsedMCPConfigurationAliases(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	if err := os.WriteFile(configPath, []byte(`{
		"mcpServers": {
			"alpha": {"command": "node", "args": ["server.js"]},
			"beta": {"command": "node", "args": ["server.js"]}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	artifact, err := configmodule.NewConfigCollector().Collect(
		context.Background(),
		collector.CollectOptions{ConfigPath: configPath, ScanID: "config-alias-writer"},
	)
	if err != nil {
		t.Fatalf("collect config aliases: %v", err)
	}
	if _, _, err := prepareObservationNodes(artifact.Graph.Nodes); err != nil {
		t.Fatalf("writer preparation rejected alias nodes: %v", err)
	}
	if _, _, err := prepareObservationEdges(artifact.Graph.Edges); err != nil {
		t.Fatalf("writer preparation rejected alias edges: %v", err)
	}
}

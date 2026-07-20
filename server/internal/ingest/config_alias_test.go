package ingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	configmodule "github.com/adithyan-ak/agenthound/modules/config"
	"github.com/adithyan-ak/agenthound/sdk/collector"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestValidatorAcceptsCollapsedMCPConfigurationAliases(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	if err := os.WriteFile(configPath, []byte(`{
		"mcpServers": {
			"beta": {"command": "node", "args": ["server.js"]},
			"alpha": {"command": "node", "args": ["server.js"]}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	artifact, err := configmodule.NewConfigCollector().Collect(
		context.Background(),
		collector.CollectOptions{
			Origin:     testCollectionOrigin,
			ConfigPath: configPath,
			ScanID:     "config-alias-validation",
		},
	)
	if err != nil {
		t.Fatalf("collect config aliases: %v", err)
	}
	wire, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal collector artifact: %v", err)
	}
	var decoded sdkingest.IngestData
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal collector artifact: %v", err)
	}
	if err := NewValidator().Validate(&decoded); err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			t.Fatalf("strict validator rejected collapsed aliases: %+v", validationErr.Errors)
		}
		t.Fatalf("strict validator rejected collapsed aliases: %v", err)
	}
}

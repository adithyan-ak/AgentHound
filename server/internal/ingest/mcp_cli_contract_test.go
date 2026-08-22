package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestProductionCLIComposesValidatorCompatibleMCPEnvelope(t *testing.T) {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "cli-contract", Version: "1.0.0"}, nil)
	httpServer := httptest.NewServer(mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	))
	defer httpServer.Close()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	bin := filepath.Join(t.TempDir(), "agenthound")
	build := exec.Command("go", "build", "-o", bin, "./collector/cmd/agenthound")
	build.Dir = repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build collector: %v\n%s", err, output)
	}

	home, project := t.TempDir(), t.TempDir()
	configPath := filepath.Join(project, ".vscode", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"servers":{"contract":{"type":"http","url":"` + httpServer.URL + `"}}}`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(t.TempDir(), "mcp.json")
	command := exec.Command(bin, "scan", "--stealth", "--timeout", "30s", "--output", artifact, "--quiet")
	command.Dir = project
	command.Env = append(
		os.Environ(),
		"HOME="+home,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run collector: %v\n%s", err, output)
	}

	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var envelope sdkingest.IngestData
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode CLI artifact: %v", err)
	}
	if err := NewValidator().Validate(&envelope); err != nil {
		if validation, ok := err.(*ValidationError); ok {
			t.Logf("validation errors: %+v", validation.Errors)
			for _, field := range validation.Errors {
				var index int
				if _, scanErr := fmt.Sscanf(field.Path, "meta.collection.outcomes[%d].coverage_key", &index); scanErr == nil && index < len(envelope.Meta.Collection.Outcomes) {
					t.Logf("invalid outcome %d: %+v", index, envelope.Meta.Collection.Outcomes[index])
				}
			}
		}
		t.Fatalf("production validator rejected CLI artifact: %v", err)
	}

	rootKey := sdkingest.CollectorRootCoverageKey("mcp")
	serverKey := sdkingest.CanonicalCoverageKey("mcp", "target", sdkingest.CanonicalURLScope(httpServer.URL))
	var foundRoot bool
	for _, root := range envelope.Meta.Collection.AuthoritativeRoots {
		if root.CoverageKey == rootKey {
			foundRoot = true
			if len(root.ChildCoverageKeys) != 1 || root.ChildCoverageKeys[0] != serverKey {
				t.Fatalf("MCP authoritative root = %+v, want %s -> [%s]", root, rootKey, serverKey)
			}
		}
	}
	if !foundRoot {
		t.Fatalf("MCP authoritative root %q missing from %+v", rootKey, envelope.Meta.Collection.AuthoritativeRoots)
	}
	methods := make(map[string]bool)
	for _, outcome := range envelope.Meta.Collection.Outcomes {
		if outcome.CoverageKey != serverKey {
			continue
		}
		if outcome.Target != httpServer.URL {
			t.Fatalf("server outcome target = %q, want %q", outcome.Target, httpServer.URL)
		}
		if methods[outcome.Method] {
			t.Fatalf("duplicate server outcome method %q", outcome.Method)
		}
		methods[outcome.Method] = true
	}
	if len(methods) == 0 {
		t.Fatal("CLI artifact contained no server outcomes")
	}
}

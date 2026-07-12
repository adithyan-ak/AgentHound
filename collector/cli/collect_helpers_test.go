package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestWriteCollectorOutput_File(t *testing.T) {
	data := testCollectorOutput()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")

	if err := writeCollectorOutput(data, outPath); err != nil {
		t.Fatalf("writeCollectorOutput: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var got ingest.IngestData
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Meta.Collector != "mcp" {
		t.Errorf("collector = %q, want %q", got.Meta.Collector, "mcp")
	}
	if len(got.Graph.Nodes) != 1 {
		t.Errorf("nodes = %d, want 1", len(got.Graph.Nodes))
	}
}

func TestWriteCollectorOutput_Stdout(t *testing.T) {
	data := testCollectorOutput()
	data.Graph.Nodes = []ingest.Node{}

	out := captureStdout(t, func() {
		if err := writeCollectorOutput(data, ""); err != nil {
			t.Fatalf("writeCollectorOutput: %v", err)
		}
	})

	var got ingest.IngestData
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", err, out)
	}
	if got.Meta.Collector != "mcp" {
		t.Errorf("collector = %q, want %q", got.Meta.Collector, "mcp")
	}
}

func testCollectorOutput() *ingest.IngestData {
	scope := ingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	data := common.NewIngestData("mcp", "scan-output-test")
	data.Meta.Collection = &ingest.CollectionReport{
		State:        ingest.OutcomeComplete,
		CoverageKeys: []string{scope},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "mcp",
			CoverageKey: scope,
			Target:      "https://mcp.example",
			Method:      "enumerate",
			State:       ingest.OutcomeComplete,
			Items:       1,
		}},
	}
	data.Graph.Nodes = []ingest.Node{{
		ID: "n1", Kinds: []string{"MCPServer"},
		Properties: map[string]any{
			"name": "srv", "auth_method": "unknown",
			"auth_assurance": "unknown", "auth_evidence": "unknown",
		},
		ObservationDomains: []string{scope},
	}}
	return data
}

func TestWriteOutputAtomic_PermsAndContent(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "atomic.json")
	want := []byte(`{"hello":"world"}`)

	if err := writeOutputAtomic(out, want); err != nil {
		t.Fatalf("writeOutputAtomic: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}

	// 0o600 is POSIX-only; on Windows the FS layer ignores the mode bits.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(out)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("perm = %v, want 0o600", mode)
		}
	}
}

func TestWriteOutputAtomic_NoTempLeftBehindOnSuccess(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	if err := writeOutputAtomic(out, []byte("data")); err != nil {
		t.Fatalf("writeOutputAtomic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected exactly one file in dir, got %d: %v", len(entries), names)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe, then returns
// what was written. Only used by tests in this package.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

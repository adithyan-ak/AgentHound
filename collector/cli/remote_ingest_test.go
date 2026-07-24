package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestRunScan_RemoteIngestSavesExactArtifactAndPrintsSummary(t *testing.T) {
	var uploaded []byte
	var submittedNodes int
	revision := int64(9)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest" {
			t.Errorf("request path = %q, want /api/v1/ingest", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q, want application/json", got)
		}
		var err error
		uploaded, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		var artifact ingest.IngestData
		if err := json.Unmarshal(uploaded, &artifact); err != nil {
			t.Errorf("decode artifact: %v", err)
		}
		submittedNodes = len(artifact.Graph.Nodes)
		_ = json.NewEncoder(w).Encode(ingest.IngestResult{
			ScanID:           artifact.Meta.ScanID,
			Outcome:          ingest.OutcomeComplete,
			ProjectionStatus: "complete",
			Submitted: ingest.FactCounts{
				Nodes: len(artifact.Graph.Nodes),
				Edges: len(artifact.Graph.Edges),
			},
			Findings:          2,
			PublishedRevision: &revision,
			Duration:          1500 * time.Millisecond,
		})
	}))
	defer server.Close()

	outputPath := filepath.Join(t.TempDir(), "backup.json")
	cmd := newScanCmdForTest()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "path", writeEmptyConfig(t))
	mustSetFlag(t, cmd, "scan-output", outputPath)
	mustSetFlag(t, cmd, "ingest", server.URL)

	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	saved, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read saved artifact: %v", err)
	}
	if !bytes.Equal(saved, uploaded) {
		t.Fatal("uploaded bytes differ from saved artifact")
	}
	for _, want := range []string{
		"Ingest complete:",
		"Artifact:  " + outputPath,
		fmt.Sprintf("Nodes:     %d", submittedNodes),
		"Edges:     0",
		"Findings:  2",
		"Duration:  1.5s",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, stdout.String())
		}
	}
	for _, want := range []string{"saved artifact:", "ingesting into"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("progress missing %q:\n%s", want, stderr.String())
		}
	}
}

func TestRunScan_RemoteIngestFailurePreservesArtifact(t *testing.T) {
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		uploaded, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":{"code":"INGEST_UNAVAILABLE","message":"try again later"}}`)
	}))
	defer server.Close()

	outputPath := filepath.Join(t.TempDir(), "retry.json")
	cmd := newScanCmdForTest()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "path", writeEmptyConfig(t))
	mustSetFlag(t, cmd, "scan-output", outputPath)
	mustSetFlag(t, cmd, "ingest", server.URL)

	err := runScan(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "INGEST_UNAVAILABLE") {
		t.Fatalf("error = %v, want sanitized ingest failure", err)
	}
	saved, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read preserved artifact: %v", readErr)
	}
	if !bytes.Equal(saved, uploaded) {
		t.Fatal("preserved artifact differs from attempted upload")
	}
}

func TestPostRemoteIngest_ReturnsSanitizedAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":{"code":"STORAGE_BINDING_UNAVAILABLE","message":"storage pair unavailable"}}`)
	}))
	defer server.Close()

	_, err := postRemoteIngest(context.Background(), server.URL, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "STORAGE_BINDING_UNAVAILABLE") ||
		!strings.Contains(err.Error(), "storage pair unavailable") {
		t.Fatalf("error = %v, want sanitized API error", err)
	}
}

func TestPostRemoteIngest_RejectsRedirect(t *testing.T) {
	destinationCalled := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalled = true
	}))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	_, err := postRemoteIngest(context.Background(), server.URL, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("error = %v, want redirect rejection", err)
	}
	if destinationCalled {
		t.Fatal("ingest payload followed redirect")
	}
}

func TestWriteRemoteIngestResult_JSONAndIncompleteValidation(t *testing.T) {
	result := &ingest.IngestResult{
		ScanID:           "scan-partial",
		Outcome:          ingest.OutcomePartial,
		ProjectionStatus: "incomplete",
		Findings:         3,
	}
	var output bytes.Buffer
	if err := writeRemoteIngestResult(&output, result, "backup.json", true); err != nil {
		t.Fatalf("writeRemoteIngestResult: %v", err)
	}
	var decoded ingest.IngestResult
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON receipt: %v", err)
	}
	if decoded.ScanID != result.ScanID || decoded.Findings != 3 {
		t.Fatalf("decoded receipt = %+v", decoded)
	}
	if err := validateRemoteIngestResult(result); err == nil {
		t.Fatal("incomplete projection returned success")
	}
}

func TestRunScan_RemoteIngestFlagValidation(t *testing.T) {
	tests := []struct {
		name   string
		ingest string
		json   string
		output string
		want   string
	}{
		{name: "json requires ingest", json: "true", want: "--json requires --ingest"},
		{name: "stdout conflicts with ingest", ingest: "http://127.0.0.1:8080", output: "-", want: "--output -"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newScanCmdForTest()
			if test.ingest != "" {
				mustSetFlag(t, cmd, "ingest", test.ingest)
			}
			if test.json != "" {
				mustSetFlag(t, cmd, "json", test.json)
			}
			if test.output != "" {
				mustSetFlag(t, cmd, "scan-output", test.output)
			}
			err := runScan(cmd, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestResolveRemoteIngestEndpoint(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080/api/v1/ingest", ok: true},
		{raw: "https://agenthound.example/api/v1/ingest", want: "https://agenthound.example/api/v1/ingest", ok: true},
		{raw: "ftp://agenthound.example", ok: false},
		{raw: "https://user:pass@agenthound.example", ok: false},
		{raw: "https://agenthound.example/other", ok: false},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := resolveRemoteIngestEndpoint(test.raw)
			if test.ok && (err != nil || got != test.want) {
				t.Fatalf("endpoint = %q, err=%v, want %q", got, err, test.want)
			}
			if !test.ok && err == nil {
				t.Fatalf("endpoint = %q, want error", got)
			}
		})
	}
}

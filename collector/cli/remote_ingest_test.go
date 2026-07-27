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

func completeRemoteIngestResult(scanID string) ingest.IngestResult {
	emptyTotals := &ingest.GraphTotals{
		NodeCounts: map[string]int64{},
		EdgeCounts: map[string]int64{},
	}
	coverageKey := ingest.CanonicalCoverageKey(
		"config",
		"remote-ingest-test",
		"/workspace/project",
	)
	revision := int64(1)
	return ingest.IngestResult{
		ScanID:              scanID,
		Outcome:             ingest.OutcomeComplete,
		ProjectionStatus:    "complete",
		Submitted:           ingest.FactCounts{},
		WriteRows:           ingest.FactCounts{},
		Findings:            0,
		GraphTotals:         ingest.FrozenGraphTotals{Before: emptyTotals, After: emptyTotals},
		NormalizationStatus: ingest.NormalizationStatusComplete,
		Collection: ingest.CollectionReport{
			State:        ingest.OutcomeComplete,
			CoverageKeys: []string{coverageKey},
			Outcomes: []ingest.CollectionOutcome{{
				Collector:   "config",
				CoverageKey: coverageKey,
				Target:      "/workspace/project",
				Method:      "remote_ingest_test",
				State:       ingest.OutcomeComplete,
			}},
		},
		Identity: ingest.IngestIdentityResult{
			CollectionPointID: "sha256:" + strings.Repeat("a", 64),
			NetworkContextID:  "sha256:" + strings.Repeat("b", 64),
			Quality:           ingest.IdentityQualityStrong,
			NetworkQuality:    ingest.IdentityQualityStrong,
			NetworkClass:      ingest.NetworkClassPrivate,
			Recognition:       "new",
		},
		PublishedRevision: &revision,
		Duration:          time.Millisecond,
	}
}

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
		result := completeRemoteIngestResult(artifact.Meta.ScanID)
		result.Submitted = ingest.FactCounts{
			Nodes: len(artifact.Graph.Nodes),
			Edges: len(artifact.Graph.Edges),
		}
		result.Findings = 2
		result.Collection = *artifact.Meta.Collection
		result.PublishedRevision = &revision
		result.Duration = 1500 * time.Millisecond
		_ = json.NewEncoder(w).Encode(result)
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

func TestRunScan_RemoteIngestWarnsBeforeUploadingPartialArtifact(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"mcpServers":`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	uploaded := false
	warnedBeforeUpload := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploaded = true
		warnedBeforeUpload = strings.Contains(
			stderr.String(),
			"WARNING: Scan artifact is partial",
		)
		var artifact ingest.IngestData
		if err := json.NewDecoder(r.Body).Decode(&artifact); err != nil {
			t.Errorf("decode artifact: %v", err)
		}
		_ = json.NewEncoder(w).Encode(ingest.IngestResult{
			ScanID:           artifact.Meta.ScanID,
			Outcome:          ingest.OutcomePartial,
			ProjectionStatus: "incomplete",
		})
	}))
	defer server.Close()

	outputPath := filepath.Join(dir, "partial-backup.json")
	cmd := newScanCmdForTest()
	cmd.SetOut(io.Discard)
	cmd.SetErr(&stderr)
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "path", malformed)
	mustSetFlag(t, cmd, "project-dir", dir)
	mustSetFlag(t, cmd, "scan-output", outputPath)
	mustSetFlag(t, cmd, "ingest", server.URL)

	if err := runScan(cmd, nil); err == nil {
		t.Fatal("partial server receipt must remain a non-zero --ingest result")
	}
	if !uploaded {
		t.Fatal("explicit --ingest did not upload the partial artifact")
	}
	if !warnedBeforeUpload {
		t.Fatalf("partial artifact was uploaded before its warning:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "may withhold graph publication") {
		t.Fatalf("partial ingest warning omitted publication consequence:\n%s", stderr.String())
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

func TestRunScan_RemoteIngestRejectsUncorrelatedReceiptBeforeSuccessOutput(t *testing.T) {
	tests := []struct {
		name           string
		responseScanID string
		want           string
	}{
		{
			name:           "different scan",
			responseScanID: "different-scan",
			want:           "does not match submitted scan_id",
		},
		{name: "missing scan", want: "scan_id must not be empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			revision := int64(9)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				result := completeRemoteIngestResult(test.responseScanID)
				result.PublishedRevision = &revision
				_ = json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()

			cmd := newScanCmdForTest()
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(io.Discard)
			mustSetFlag(t, cmd, "config", "true")
			mustSetFlag(t, cmd, "path", writeEmptyConfig(t))
			mustSetFlag(t, cmd, "scan-output", filepath.Join(t.TempDir(), "backup.json"))
			mustSetFlag(t, cmd, "ingest", server.URL)

			err := runScan(cmd, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want error containing %q", err, test.want)
			}
			if strings.Contains(stdout.String(), "Ingest complete") {
				t.Fatalf("uncorrelated receipt reported success:\n%s", stdout.String())
			}
		})
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

func TestPostRemoteIngest_RejectsMissingRequiredField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{
			"scan_id":"scan-1",
			"outcome":"complete",
			"projection_status":"complete",
			"submitted":{"nodes":1,"edges":0},
			"write_rows":{"nodes":1,"edges":0},
			"graph_totals":{"before":null,"after":null},
			"normalization_status":"complete",
			"collection":{"state":"complete"},
			"identity":{
				"collection_point_id":"cp",
				"network_context_id":"network",
				"quality":"strong",
				"network_quality":"strong",
				"network_class":"private",
				"recognition":"new"
			},
			"published_revision":9,
			"duration":1000000
		}`)
	}))
	defer server.Close()

	_, err := postRemoteIngest(context.Background(), server.URL, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), `required field "findings"`) {
		t.Fatalf("postRemoteIngest error = %v, want missing findings rejection", err)
	}
}

func TestWriteRemoteIngestResult_LimitedCoverageRemainsSuccessful(t *testing.T) {
	revision := int64(10)
	root := ingest.CanonicalCoverageKey(
		"config",
		"instruction-exact-project",
		"/workspace/project",
	)
	contract := ingest.CurrentInstructionRegistryContract()
	limited := completeRemoteIngestResult("scan-limited")
	limited.PublishedRevision = &revision
	limited.Collection = ingest.CollectionReport{
		State:        ingest.OutcomeTruncated,
		CoverageKeys: []string{root},
		AuthoritativeRoots: []ingest.CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{},
			RegistryContract:  &contract,
		}},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "config",
			CoverageKey: root,
			Target:      "/workspace/project",
			Method:      ingest.InstructionMethodExactProject,
			State:       ingest.OutcomeTruncated,
		}},
	}
	result := &limited
	receipt := &remoteIngestReceipt{result: result}

	var output bytes.Buffer
	if err := writeRemoteIngestResult(&output, receipt, "backup.json", false); err != nil {
		t.Fatalf("writeRemoteIngestResult: %v", err)
	}
	if !strings.Contains(
		output.String(),
		"Ingest complete with coverage limitations:",
	) {
		t.Fatalf("limited receipt did not disclose coverage:\n%s", output.String())
	}
	if err := validateRemoteIngestResult(result); err != nil {
		t.Fatalf("published limited receipt returned failure: %v", err)
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
	incomplete := completeRemoteIngestResult("scan-partial")
	incomplete.Outcome = ingest.OutcomePartial
	incomplete.ProjectionStatus = "incomplete"
	incomplete.Findings = 3
	incomplete.PublishedRevision = nil
	result := &incomplete
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &remoteIngestReceipt{
		result: result,
		raw:    raw,
	}
	var output bytes.Buffer
	if err := writeRemoteIngestResult(&output, receipt, "backup.json", true); err != nil {
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

func TestDecodeRemoteIngestResult_RejectsMalformedV1Receipts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "missing coverage keys",
			mutate: func(document map[string]any) {
				delete(remoteDocumentObject(document, "collection"), "coverage_keys")
			},
			want: "collection.coverage_keys",
		},
		{
			name: "null coverage keys",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "collection")["coverage_keys"] = nil
			},
			want: "collection.coverage_keys",
		},
		{
			name: "empty coverage keys",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "collection")["coverage_keys"] = []any{}
			},
			want: "coverage_keys must be a nonempty array",
		},
		{
			name: "missing outcomes",
			mutate: func(document map[string]any) {
				delete(remoteDocumentObject(document, "collection"), "outcomes")
			},
			want: "collection.outcomes",
		},
		{
			name: "null outcomes",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "collection")["outcomes"] = nil
			},
			want: "collection.outcomes",
		},
		{
			name: "empty outcomes",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "collection")["outcomes"] = []any{}
			},
			want: "outcomes must be a nonempty array",
		},
		{
			name: "noncanonical coverage key",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "collection")["coverage_keys"] =
					[]any{"config:target:sha256:not-a-digest"}
			},
			want: "coverage_keys[0] is not canonical",
		},
		{
			name: "duplicate coverage key",
			mutate: func(document map[string]any) {
				collection := remoteDocumentObject(document, "collection")
				key := remoteDocumentArray(collection, "coverage_keys")[0]
				collection["coverage_keys"] = []any{key, key}
			},
			want: "coverage_keys[1] duplicates",
		},
		{
			name: "outcome key not declared",
			mutate: func(document map[string]any) {
				collection := remoteDocumentObject(document, "collection")
				outcome := remoteDocumentArray(collection, "outcomes")[0]
				remoteDocumentValueObject(outcome)["coverage_key"] =
					ingest.CanonicalCoverageKey("config", "other", "/other")
			},
			want: "coverage_key is not declared",
		},
		{
			name: "invalid collection enum",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "collection")["state"] = "clean"
			},
			want: "collection.state",
		},
		{
			name: "invalid outcome enum",
			mutate: func(document map[string]any) {
				collection := remoteDocumentObject(document, "collection")
				outcome := remoteDocumentArray(collection, "outcomes")[0]
				remoteDocumentValueObject(outcome)["state"] = "clean"
			},
			want: "collection.outcomes[0].state",
		},
		{
			name: "invalid projection enum",
			mutate: func(document map[string]any) {
				document["projection_status"] = "published"
			},
			want: "projection_status",
		},
		{
			name: "invalid normalization enum",
			mutate: func(document map[string]any) {
				document["normalization_status"] = "ok"
			},
			want: "normalization_status",
		},
		{
			name: "invalid identity hash",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "identity")["collection_point_id"] =
					"sha256:not-a-digest"
			},
			want: "identity.collection_point_id",
		},
		{
			name: "invalid identity enum",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "identity")["recognition"] = "trusted"
			},
			want: "identity.recognition",
		},
		{
			name: "incomplete graph totals",
			mutate: func(document map[string]any) {
				graphTotals := remoteDocumentObject(document, "graph_totals")
				before := remoteDocumentValueObject(graphTotals["before"])
				delete(before, "total_nodes")
			},
			want: "graph_totals.before.total_nodes",
		},
		{
			name: "negative submitted count",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "submitted")["nodes"] = -1
			},
			want: "submitted counts must be non-negative",
		},
		{
			name: "negative written count",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "write_rows")["edges"] = -1
			},
			want: "write_rows counts must be non-negative",
		},
		{
			name: "negative finding count",
			mutate: func(document map[string]any) {
				document["findings"] = -1
			},
			want: "findings must be non-negative",
		},
		{
			name: "negative graph count",
			mutate: func(document map[string]any) {
				graphTotals := remoteDocumentObject(document, "graph_totals")
				remoteDocumentValueObject(graphTotals["after"])["total_edges"] = -1
			},
			want: "graph_totals.after totals must be non-negative",
		},
		{
			name: "null successful snapshot",
			mutate: func(document map[string]any) {
				remoteDocumentObject(document, "graph_totals")["after"] = nil
			},
			want: "complete projection requires before and after graph totals",
		},
		{
			name: "missing published revision",
			mutate: func(document map[string]any) {
				delete(document, "published_revision")
			},
			want: "complete projection requires published_revision",
		},
		{
			name: "zero published revision",
			mutate: func(document map[string]any) {
				document["published_revision"] = 0
			},
			want: "published_revision must be at least 1",
		},
		{
			name: "unknown field",
			mutate: func(document map[string]any) {
				document["legacy_success"] = true
			},
			want: "unknown field",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := remoteIngestResultDocument(
				t,
				completeRemoteIngestResult("scan-strict-v1"),
			)
			test.mutate(document)
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decodeRemoteIngestResult(body)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decode error = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestDecodeRemoteIngestResult_AcceptsPublishedLimitedCollections(t *testing.T) {
	for _, state := range []ingest.OutcomeState{
		ingest.OutcomePartial,
		ingest.OutcomeFailed,
		ingest.OutcomeTruncated,
	} {
		t.Run(string(state), func(t *testing.T) {
			result := completeRemoteIngestResult("scan-limited-" + string(state))
			result.Collection.State = state
			result.Collection.Outcomes[0].State = state
			body, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeRemoteIngestResult(body)
			if err != nil {
				t.Fatalf("decode published %s collection: %v", state, err)
			}
			if !remoteIngestComplete(decoded) {
				t.Fatalf("published %s collection was not successful", state)
			}
			if !remoteResultCoverageLimited(decoded) {
				t.Fatalf("published %s collection lost its coverage warning", state)
			}
		})
	}
}

func TestRunScan_RemoteIngestRejectsMalformedReceiptBeforeSuccessOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var artifact ingest.IngestData
		if err := json.NewDecoder(r.Body).Decode(&artifact); err != nil {
			t.Errorf("decode artifact: %v", err)
		}
		result := completeRemoteIngestResult(artifact.Meta.ScanID)
		result.Identity.CollectionPointID = "sha256:not-a-digest"
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	cmd := newScanCmdForTest()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(io.Discard)
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "path", writeEmptyConfig(t))
	mustSetFlag(t, cmd, "scan-output", filepath.Join(t.TempDir(), "backup.json"))
	mustSetFlag(t, cmd, "ingest", server.URL)

	err := runScan(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "identity.collection_point_id") {
		t.Fatalf("runScan error = %v, want malformed receipt rejection", err)
	}
	if strings.Contains(stdout.String(), "Ingest complete") {
		t.Fatalf("malformed receipt reported success:\n%s", stdout.String())
	}
}

func remoteIngestResultDocument(
	t *testing.T,
	result ingest.IngestResult,
) map[string]any {
	t.Helper()
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func remoteDocumentObject(document map[string]any, field string) map[string]any {
	return remoteDocumentValueObject(document[field])
}

func remoteDocumentValueObject(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		panic(fmt.Sprintf("test document value has type %T, want object", value))
	}
	return object
}

func remoteDocumentArray(document map[string]any, field string) []any {
	array, ok := document[field].([]any)
	if !ok {
		panic(fmt.Sprintf("test document field %q has type %T, want array", field, document[field]))
	}
	return array
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

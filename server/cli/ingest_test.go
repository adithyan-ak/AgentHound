package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	serveringest "github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestIngestCommandRejectsUnsupportedVersionBeforeBootstrap(t *testing.T) {
	data := common.NewIngestData("scan", "old-cli-artifact")
	data.Meta.Version = ingest.CurrentVersion - 1
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(encoded, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["removed_v4_field"] = true
	encoded, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	original := bootstrapForIngest
	t.Cleanup(func() { bootstrapForIngest = original })
	bootstrapCalled := false
	bootstrapForIngest = func(context.Context) (*Infrastructure, func(), error) {
		bootstrapCalled = true
		return nil, nil, errors.New("bootstrap must not run")
	}

	err = ingestCmd.RunE(ingestCmd, []string{path})
	if bootstrapCalled {
		t.Fatal("Bootstrap ran before version preflight")
	}
	var versionErr *serveringest.UnsupportedVersionError
	if !errors.As(err, &versionErr) ||
		!strings.Contains(err.Error(), "unsupported") ||
		!strings.Contains(err.Error(), "recollect") {
		t.Fatalf("error = %T %v, want actionable unsupported-version error", err, err)
	}
}

func TestWriteIngestResultComplete(t *testing.T) {
	revision := int64(7)
	result := &ingest.IngestResult{
		ScanID:            "scan-complete",
		Outcome:           ingest.OutcomeComplete,
		ProjectionStatus:  model.ProjectionComplete,
		PublishedRevision: &revision,
		WriteRows:         ingest.FactCounts{Nodes: 3, Edges: 2},
		Duration:          1500 * time.Millisecond,
		Identity: ingest.IngestIdentityResult{
			CollectionPointID: "sha256:" + strings.Repeat("a", 64),
			NetworkContextID:  "sha256:" + strings.Repeat("b", 64),
			Quality:           ingest.IdentityQualityStrong,
			NetworkQuality:    ingest.IdentityQualityUnknown,
			NetworkClass:      ingest.NetworkClassPrivate,
			Display:           ingest.CollectionDisplayLabels{Hostname: "target-01", OS: "linux", Architecture: "amd64"},
			Recognition:       "new",
		},
	}

	var output bytes.Buffer
	if err := writeIngestResult(&output, result); err != nil {
		t.Fatalf("writeIngestResult returned error: %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"Ingest complete:",
		"Scan ID:            scan-complete",
		"Outcome:            complete",
		"Projection status:  complete",
		"Collection point:   target-01 · linux amd64 (strong, new)",
		"Collection point ID: sha256:aaaaaaaa",
		"Network context:    sha256:bbbbbbbb",
		"(private, unknown)",
		"Published revision: 7",
		"Node write rows:    3",
		"Edge write rows:    2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestWriteIngestResultLimitedDeepCoverageRemainsSuccessful(t *testing.T) {
	revision := int64(8)
	root := ingest.CanonicalCoverageKey("config", "instruction-deep", "/home/example")
	contract := ingest.CurrentInstructionRegistryContract()
	result := &ingest.IngestResult{
		ScanID:            "scan-limited",
		Outcome:           ingest.OutcomeComplete,
		ProjectionStatus:  model.ProjectionComplete,
		PublishedRevision: &revision,
		Collection: ingest.CollectionReport{
			State:        ingest.OutcomeTruncated,
			CoverageKeys: []string{root},
			AuthoritativeRoots: []ingest.CoverageRoot{{
				CoverageKey:      root,
				RegistryContract: &contract,
			}},
			Outcomes: []ingest.CollectionOutcome{{
				Collector:   "config",
				CoverageKey: root,
				Method:      ingest.InstructionMethodDeep,
				State:       ingest.OutcomeTruncated,
			}},
		},
	}

	var output bytes.Buffer
	if err := writeIngestResult(&output, result); err != nil {
		t.Fatalf("usable limited-coverage result returned error: %v", err)
	}
	if !strings.Contains(output.String(), "Ingest complete with coverage limitations:") {
		t.Fatalf("output did not disclose limited coverage:\n%s", output.String())
	}
}

func TestFinishIngestCommandRendersFailedResultAndPreservesPipelineError(t *testing.T) {
	pipelineErr := errors.New("edge batch 2 committed 1000 rows before failure")
	result := &ingest.IngestResult{
		ScanID:           "scan-write-failure",
		Outcome:          ingest.OutcomeFailed,
		ProjectionStatus: model.ProjectionIncomplete,
		WriteRows:        ingest.FactCounts{Nodes: 3, Edges: 1000},
		Stages: []ingest.StageResult{{
			Name:     "write_edges",
			State:    ingest.OutcomeFailed,
			Required: true,
			Error:    pipelineErr.Error(),
		}},
	}

	var output bytes.Buffer
	err := finishIngestCommand(&output, result, pipelineErr)
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("finish error = %v, want wrapped pipeline error", err)
	}
	for _, want := range []string{
		"Ingest failed:",
		"Scan ID:            scan-write-failure",
		"Node write rows:    3",
		"Edge write rows:    1000",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteIngestResultIncomplete(t *testing.T) {
	result := &ingest.IngestResult{
		ScanID:           "scan-incomplete",
		Outcome:          ingest.OutcomePartial,
		ProjectionStatus: model.ProjectionIncomplete,
		WriteRows:        ingest.FactCounts{Nodes: 8, Edges: 4},
		Stages: []ingest.StageResult{
			{
				Name:     "observation_completeness",
				State:    ingest.OutcomePartial,
				Required: true,
				Error:    "8 property-incomplete nodes, 4 property-incomplete relationships",
			},
			{
				Name:     "publication",
				State:    ingest.OutcomeNotApplicable,
				Required: true,
				Error:    "publication withheld",
			},
		},
	}

	var output bytes.Buffer
	err := writeIngestResult(&output, result)
	if err == nil {
		t.Fatal("writeIngestResult returned nil error for incomplete result")
	}

	got := output.String()
	for _, want := range []string{
		"Ingest incomplete:",
		"Outcome:            partial",
		"Projection status:  incomplete",
		"Published revision: unavailable",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}

	wantErr := "ingest did not publish a complete projection: " +
		"outcome=partial projection=incomplete; " +
		"stage observation_completeness=partial: " +
		"8 property-incomplete nodes, 4 property-incomplete relationships"
	if err.Error() != wantErr {
		t.Fatalf("error = %q, want %q", err, wantErr)
	}
}

func TestWriteIngestResultPropagatesOutputFailure(t *testing.T) {
	revision := int64(7)
	writeErr := errors.New("terminal unavailable")
	result := &ingest.IngestResult{
		ScanID:            "scan-complete",
		Outcome:           ingest.OutcomeComplete,
		ProjectionStatus:  model.ProjectionComplete,
		PublishedRevision: &revision,
	}

	err := writeIngestResult(errorWriter{err: writeErr}, result)
	if !errors.Is(err, writeErr) {
		t.Fatalf("writeIngestResult error = %v, want wrapped output error", err)
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

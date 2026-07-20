package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestWriteIngestResultComplete(t *testing.T) {
	revision := int64(7)
	result := &ingest.IngestResult{
		ScanID:            "scan-complete",
		Outcome:           ingest.OutcomeComplete,
		ProjectionStatus:  model.ProjectionComplete,
		PublishedRevision: &revision,
		WriteRows:         ingest.FactCounts{Nodes: 3, Edges: 2},
		Duration:          1500 * time.Millisecond,
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
		"Published revision: 7",
		"Node write rows:    3",
		"Edge write rows:    2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
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

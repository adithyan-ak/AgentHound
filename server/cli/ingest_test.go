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
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestIngestCommandRejectsUnsupportedV1ContractBeforeBootstrap(t *testing.T) {
	current := common.NewIngestData("scan", "unsupported-cli-artifact")
	currentEncoded, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	var unknownField map[string]any
	if err := json.Unmarshal(currentEncoded, &unknownField); err != nil {
		t.Fatal(err)
	}
	unknownField["unrecognized_field"] = true
	unknownEncoded, err := json.Marshal(unknownField)
	if err != nil {
		t.Fatal(err)
	}

	original := bootstrapForIngest
	t.Cleanup(func() { bootstrapForIngest = original })
	bootstrapCalled := false
	bootstrapForIngest = func(context.Context) (*Infrastructure, func(), error) {
		bootstrapCalled = true
		return nil, nil, errors.New("bootstrap must not run")
	}

	nonV1 := common.NewIngestData("scan", "non-v1-cli-artifact")
	nonV1.Meta.Version = ingest.CurrentVersion + 1
	nonV1Encoded, err := json.Marshal(nonV1)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"malformed":     []byte(`{"meta":`),
		"missing":       []byte(`{"graph":{"nodes":[],"edges":[]}}`),
		"zero":          []byte(`{"meta":{"version":0}}`),
		"non-v1":        nonV1Encoded,
		"unknown field": unknownEncoded,
	} {
		t.Run(name, func(t *testing.T) {
			bootstrapCalled = false
			path := filepath.Join(t.TempDir(), "unsupported.json")
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			err := ingestCmd.RunE(ingestCmd, []string{path})
			if bootstrapCalled {
				t.Fatal("Bootstrap ran before contract preflight")
			}
			if err == nil || !strings.Contains(err.Error(), "V1") {
				t.Fatalf("error = %T %v, want supported contract diagnostic", err, err)
			}
			if name == "non-v1" {
				for _, want := range []string{"contract V2", `collector "dev"`, "upgrade agenthound-server"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error missing %q: %v", want, err)
					}
				}
			}
		})
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
		Collection: ingest.CollectionReport{
			State:        ingest.OutcomeComplete,
			CoverageKeys: []string{"config:path:sha256:" + strings.Repeat("c", 64)},
			Outcomes: []ingest.CollectionOutcome{{
				Collector:   "config",
				CoverageKey: "config:path:sha256:" + strings.Repeat("c", 64),
				Method:      "config_discovery",
				State:       ingest.OutcomeComplete,
			}},
		},
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

func TestFinishIngestCommandReportsCompatibilityOnSuccess(t *testing.T) {
	revision := int64(7)
	result := &ingest.IngestResult{
		ScanID:            "scan-compatible",
		Outcome:           ingest.OutcomeComplete,
		ProjectionStatus:  model.ProjectionComplete,
		PublishedRevision: &revision,
		Collection:        ingest.CollectionReport{State: ingest.OutcomeComplete},
	}

	var output bytes.Buffer
	err := finishIngestCommand(&output, result, nil, ingestCompatibility{
		CollectorVersion: "1.0.0",
		ContractVersion:  ingest.CurrentVersion,
		ServerVersion:    "1.1.1 (commit: test)",
	})
	if err != nil {
		t.Fatalf("finishIngestCommand returned error: %v", err)
	}
	for _, want := range []string{
		`Collector version:  "1.0.0"`,
		"Artifact contract:  V1",
		"Server version:     1.1.1 (commit: test)",
		"Ingest complete",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteIngestCompatibilityEscapesUntrustedCollectorVersion(t *testing.T) {
	var output bytes.Buffer
	err := writeIngestCompatibility(&output, ingestCompatibility{
		CollectorVersion: "\x1b[31mdev\nspoof",
		ContractVersion:  ingest.CurrentVersion,
		ServerVersion:    "1.1.1",
	})
	if err != nil {
		t.Fatalf("writeIngestCompatibility returned error: %v", err)
	}
	if strings.Contains(output.String(), "\x1b") || strings.Contains(output.String(), "dev\nspoof") {
		t.Fatalf("compatibility output contains raw terminal controls: %q", output.String())
	}
	if !strings.Contains(output.String(), `"\x1b[31mdev\nspoof"`) {
		t.Fatalf("compatibility output did not quote collector version: %q", output.String())
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

func TestWriteIngestResultPublishedIncompleteExactCoverageRemainsSuccessful(t *testing.T) {
	revision := int64(9)
	root := ingest.CanonicalCoverageKey(
		"config",
		"instruction-exact-user",
		"/home/example",
	)
	contract := ingest.CurrentInstructionRegistryContract()
	result := &ingest.IngestResult{
		ScanID:            "scan-exact-limited",
		Outcome:           ingest.OutcomeComplete,
		ProjectionStatus:  model.ProjectionComplete,
		PublishedRevision: &revision,
		Warnings:          []string{ingest.CoverageLimitationWarning},
		Collection: ingest.CollectionReport{
			State:        ingest.OutcomePartial,
			CoverageKeys: []string{root},
			AuthoritativeRoots: []ingest.CoverageRoot{{
				CoverageKey:      root,
				RegistryContract: &contract,
			}},
			Outcomes: []ingest.CollectionOutcome{{
				Collector:   "config",
				CoverageKey: root,
				Method:      ingest.InstructionMethodExactUser,
				State:       ingest.OutcomePartial,
				Error:       "permission denied",
			}},
		},
	}

	var output bytes.Buffer
	if err := writeIngestResult(&output, result); err != nil {
		t.Fatalf("published exact limited-coverage result returned error: %v", err)
	}
	for _, want := range []string{
		"Ingest complete with coverage limitations:",
		"Warnings:           1",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(ingest.CoverageLimitationWarning, "instruction") ||
		!strings.Contains(ingest.CoverageLimitationWarning, "not proof of absence") {
		t.Fatalf(
			"warning is not generalized to incomplete collection coverage: %q",
			ingest.CoverageLimitationWarning,
		)
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
	err := finishIngestCommand(&output, result, pipelineErr, ingestCompatibility{
		CollectorVersion: "1.0.0",
		ContractVersion:  ingest.CurrentVersion,
		ServerVersion:    "1.1.1 (commit: test)",
	})
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("finish error = %v, want wrapped pipeline error", err)
	}
	for _, want := range []string{
		`Collector version:  "1.0.0"`,
		"Artifact contract:  V1",
		"Server version:     1.1.1 (commit: test)",
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

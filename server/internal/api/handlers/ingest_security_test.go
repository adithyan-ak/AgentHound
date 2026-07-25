package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

// TestMaxIngestBodySizeValue locks the 100 MB upper bound. If a future change
// loosens this, ingest becomes a DoS vector — fail loudly.
func TestMaxIngestBodySizeValue(t *testing.T) {
	const want = 100 << 20 // 100 MB
	if maxIngestBodySize != want {
		t.Errorf("maxIngestBodySize = %d, want %d (100 MB)", maxIngestBodySize, want)
	}
}

// TestIngestRejectsInvalidJSON is a regression for the early-return path
// that prevented unparseable bodies from reaching the validator.
func TestIngestRejectsInvalidJSON(t *testing.T) {
	h := NewIngestHandler(nil)

	body := strings.NewReader(`{"bad json`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Handle(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "VALIDATION_ERROR") {
		t.Errorf("body should contain VALIDATION_ERROR, got %s", rec.Body.String())
	}
}

func TestIngestRejectsUnsupportedVersionWithStructuredDetails(t *testing.T) {
	data := common.NewIngestData("scan", "old-version")
	data.Meta.Version = sdkingest.CurrentVersion - 1
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["removed_v4_field"] = true
	body, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	NewIngestHandler(nil).Handle(
		rec,
		httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body)),
	)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var response ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "UNSUPPORTED_INGEST_VERSION" {
		t.Fatalf("error code = %q", response.Error.Code)
	}
	details, ok := response.Error.Details.(map[string]any)
	if !ok {
		t.Fatalf("details = %T %+v", response.Error.Details, response.Error.Details)
	}
	if details["received_version"] != float64(sdkingest.CurrentVersion-1) ||
		details["supported_version"] != float64(sdkingest.CurrentVersion) {
		t.Fatalf("details = %+v", details)
	}
	if !strings.Contains(response.Error.Message, "recollect") {
		t.Fatalf("message is not actionable: %q", response.Error.Message)
	}
}

func TestIngestRejectsRegistryContractMismatchWithStructuredDetails(t *testing.T) {
	data := common.NewIngestData("config", "foreign-registry")
	root := sdkingest.CanonicalCoverageKey("config", "instruction-deep", "/home/example")
	contract := sdkingest.CurrentInstructionRegistryContract()
	contract.Generation++
	data.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: []string{root},
		AuthoritativeRoots: []sdkingest.CoverageRoot{{
			CoverageKey: root, ChildCoverageKeys: []string{}, RegistryContract: &contract,
		}},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector: "config", CoverageKey: root, Target: "/home/example",
			Method: sdkingest.InstructionMethodDeep, State: sdkingest.OutcomeComplete,
		}},
	}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	NewIngestHandler(nil).Handle(
		rec,
		httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body)),
	)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var response ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "REGISTRY_CONTRACT_MISMATCH" {
		t.Fatalf("error code = %q", response.Error.Code)
	}
	if !strings.Contains(response.Error.Message, "upgrade the collector and server together") {
		t.Fatalf("message is not actionable: %q", response.Error.Message)
	}
}

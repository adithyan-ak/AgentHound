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
func TestIngestRejectsInvalidJSONAsGenericV1ContractError(t *testing.T) {
	h := NewIngestHandler(nil)

	body := strings.NewReader(`{"bad json`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Handle(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "UNSUPPORTED_V1_CONTRACT") {
		t.Errorf("body should contain UNSUPPORTED_V1_CONTRACT, got %s", rec.Body.String())
	}
}

func TestIngestRejectsUnsupportedShapesAsGenericV1ContractError(t *testing.T) {
	current := common.NewIngestData("scan", "unsupported-shape")
	currentBody, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	var unsupported map[string]any
	if err := json.Unmarshal(currentBody, &unsupported); err != nil {
		t.Fatal(err)
	}
	unsupported["unknown_contract_field"] = true
	unknownBody, err := json.Marshal(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	missingVersion := common.NewIngestData("scan", "missing-version")
	missingVersion.Meta.Version = 0
	missingBody, err := json.Marshal(missingVersion)
	if err != nil {
		t.Fatal(err)
	}
	nonV1 := common.NewIngestData("scan", "non-v1-version")
	nonV1.Meta.Version = sdkingest.CurrentVersion + 1
	nonV1Body, err := json.Marshal(nonV1)
	if err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string][]byte{
		"missing version": missingBody,
		"non-v1 version":  nonV1Body,
		"unknown field":   unknownBody,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			NewIngestHandler(nil).Handle(
				rec,
				httptest.NewRequest(
					http.MethodPost,
					"/api/v1/ingest",
					bytes.NewReader(body),
				),
			)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			var response ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Error.Code != "UNSUPPORTED_V1_CONTRACT" {
				t.Fatalf("error code = %q", response.Error.Code)
			}
			if response.Error.Message != "unsupported V1 ingest contract" ||
				response.Error.Details != nil {
				t.Fatalf(
					"error = %+v, want generic V1 contract rejection",
					response.Error,
				)
			}
		})
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
	if !strings.Contains(response.Error.Message, "V1 artifact") {
		t.Fatalf("message is not actionable: %q", response.Error.Message)
	}
}

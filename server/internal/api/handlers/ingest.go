package handlers

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/adithyan-ak/agenthound/server/internal/ingest"
)

type IngestHandler struct {
	pipeline *ingest.Pipeline
}

func NewIngestHandler(pipeline *ingest.Pipeline) *IngestHandler {
	return &IngestHandler{pipeline: pipeline}
}

const maxIngestBodySize = 100 << 20 // 100 MB

func (h *IngestHandler) Handle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodySize)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteValidationError(w, "invalid JSON payload")
		return
	}
	version, err := sdkingest.DecodeVersion(body)
	if err != nil {
		WriteValidationError(w, "invalid JSON payload")
		return
	}
	if version != sdkingest.CurrentVersion {
		probe := sdkingest.IngestData{}
		probe.Meta.Version = version
		if writeIngestContractError(w, ingest.Preflight(&probe)) {
			return
		}
	}

	var data sdkingest.IngestData
	if err := sdkingest.DecodeStrict(bytes.NewReader(body), &data); err != nil {
		WriteValidationError(w, "invalid JSON payload")
		return
	}
	if err := ingest.Preflight(&data); err != nil {
		if writeIngestContractError(w, err) {
			return
		}
		var ve *ingest.ValidationError
		if errors.As(err, &ve) {
			WriteJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: ErrorDetail{
					Code:    "VALIDATION_ERROR",
					Message: "validation failed",
					Details: ve.Errors,
				},
			})
			return
		}
		WriteValidationError(w, err.Error())
		return
	}

	result, err := h.pipeline.Ingest(r.Context(), &data)
	if err != nil {
		if writeIngestContractError(w, err) {
			return
		}
		if binding.IsStorageError(err) {
			slog.Error("storage binding admission failed", "error", err)
			WriteJSON(w, http.StatusServiceUnavailable, ErrorResponse{
				Error: ErrorDetail{
					Code:    "STORAGE_BINDING_UNAVAILABLE",
					Message: "The PostgreSQL and Neo4j storage pair could not be verified.",
				},
			})
			return
		}
		var ve *ingest.ValidationError
		if errors.As(err, &ve) {
			WriteJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: ErrorDetail{
					Code:    "VALIDATION_ERROR",
					Message: "validation failed",
					Details: ve.Errors,
				},
			})
			return
		}
		if result != nil {
			slog.Error("ingest failed after graph mutation",
				"error", err,
				"scan_id", result.ScanID,
				"node_write_rows", result.WriteRows.Nodes,
				"edge_write_rows", result.WriteRows.Edges,
			)
			WriteJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: ErrorDetail{
					Code:    "INGEST_FAILED",
					Message: "Ingest failed after partial graph mutation.",
					Details: result,
				},
			})
			return
		}
		WriteInternalError(w, r, err)
		return
	}

	WriteJSON(w, http.StatusOK, result)
}

func writeIngestContractError(w http.ResponseWriter, err error) bool {
	var versionErr *ingest.UnsupportedVersionError
	if errors.As(err, &versionErr) {
		WriteJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "UNSUPPORTED_INGEST_VERSION",
				Message: versionErr.Error(),
				Details: versionErr,
			},
		})
		return true
	}
	var contractErr *ingest.RegistryContractMismatchError
	if errors.As(err, &contractErr) {
		WriteJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "REGISTRY_CONTRACT_MISMATCH",
				Message: contractErr.Error(),
				Details: contractErr,
			},
		})
		return true
	}
	return false
}

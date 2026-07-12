package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// GenerationStageOutcome reports one promoted generation's per-stage ingest
// outcomes (write / post_processing / snapshot / promotion). It is surfaced in
// Completeness so a client sees exactly which stages succeeded for each current
// scope rather than only a rolled-up boolean — a generation can be "current"
// yet have, say, a partial post-processing stage, and the UI must be able to
// disclose that precisely.
type GenerationStageOutcome struct {
	GenerationID   string                       `json:"generation_id"`
	Collector      string                       `json:"collector,omitempty"`
	Scope          string                       `json:"scope,omitempty"`
	CoverageStatus string                       `json:"coverage_status"`
	StageStates    map[string]ingest.StageState `json:"stage_states,omitempty"`
}

// Completeness describes whether a scan/generation-scoped read reflects a
// fully materialized, promoted view. It exists so a client can never coalesce
// a partial, stale, or degraded read into an all-clear/zero verdict: when
// Complete is false the accompanying totals and verdicts are NOT authoritative.
type Completeness struct {
	// Complete is true only when at least one current generation exists and
	// every current scope reported complete coverage.
	Complete bool `json:"complete"`
	// CoverageStatus is the rolled-up collection status across current
	// generations: complete|partial|failed|unknown, or "none" when nothing
	// has been promoted yet.
	CoverageStatus string `json:"coverage_status"`
	// GenerationIDs are the promoted generations this read was scoped to.
	GenerationIDs []string `json:"generation_ids"`
	// Truncated is true when the read hit its page/row limit and more data
	// exists beyond what was returned.
	Truncated bool `json:"truncated"`
	// CapturedAt / CompletedAt are the newest collection-capture and server
	// ingest-completion times across the current generations.
	CapturedAt  *time.Time `json:"captured_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	// SourceErrors carries any recorded per-scope collection/ingest errors so
	// a caller can disclose why the view is incomplete.
	SourceErrors []string `json:"source_errors,omitempty"`
	// Generations carries the per-current-generation stage outcomes so
	// completeness discloses exactly which ingest stages succeeded for each
	// promoted scope, not just a single rolled-up flag.
	Generations []GenerationStageOutcome `json:"generations,omitempty"`
}

// Page is the completeness-aware envelope for scoped list reads. Total is a
// pointer so it can be suppressed (null) until the underlying view is complete
// — a global count over a partial view would be a false verdict.
type Page[T any] struct {
	Items        []T          `json:"items"`
	Total        *int         `json:"total"`
	Limit        int          `json:"limit"`
	Offset       int          `json:"offset"`
	NextOffset   *int         `json:"next_offset,omitempty"`
	Completeness Completeness `json:"completeness"`
}

// newGraphPage builds a Page envelope for graph reads that page without a
// separate count query. When the page is truncated (a full page was returned),
// more data exists beyond it: total is suppressed and next_offset is set. When
// the page is short and the view is complete, this offset is exhausted so
// total is authoritative (offset + len).
func newGraphPage[T any](items []T, offsetPlusLen, limit, offset int, c Completeness) Page[T] {
	if items == nil {
		items = []T{}
	}
	p := Page[T]{Items: items, Limit: limit, Offset: offset, Completeness: c}
	if c.Truncated {
		next := offset + limit
		p.NextOffset = &next
		return p
	}
	if c.Complete {
		t := offsetPlusLen
		p.Total = &t
	}
	return p
}

// newPage builds a Page envelope. When the completeness is incomplete, total
// is suppressed (nil). next_offset is set only when a full page was returned
// and the view is complete (so paging past an incomplete view is not implied).
func newPage[T any](items []T, total, limit, offset int, c Completeness) Page[T] {
	if items == nil {
		items = []T{}
	}
	p := Page[T]{Items: items, Limit: limit, Offset: offset, Completeness: c}
	if c.Complete {
		t := total
		p.Total = &t
		if offset+len(items) < total {
			next := offset + limit
			p.NextOffset = &next
		}
	}
	return p
}

type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorResponse{
		Error: ErrorDetail{Code: code, Message: message},
	})
}

func WriteInternalError(w http.ResponseWriter, r *http.Request, err error) {
	reqID := chimw.GetReqID(r.Context())
	slog.Error("internal error", "error", err, "request_id", reqID)
	WriteJSON(w, http.StatusInternalServerError, ErrorResponse{
		Error: ErrorDetail{
			Code:    "INTERNAL_ERROR",
			Message: "An internal error occurred. Reference: " + reqID,
		},
	})
}

func WriteValidationError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusBadRequest, "VALIDATION_ERROR", message)
}

func WriteNotFound(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusNotFound, "NOT_FOUND", message)
}

func WriteServiceError(w http.ResponseWriter, service string) {
	WriteError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", service+" is unavailable")
}

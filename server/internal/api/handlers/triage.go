package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
)

// triageStore is the subset of *appdb.FindingStore the triage handler
// needs. Defined as an interface so the handler can be unit-tested with a
// recorder and so a nil store degrades to a clean 503.
type triageStore interface {
	GetTriage(ctx context.Context, fingerprint string) (*model.TriageState, error)
	UpsertTriage(ctx context.Context, fingerprint, status, note string) (*model.TriageState, error)
}

type TriageHandler struct {
	store triageStore
}

func NewTriageHandler(store *appdb.FindingStore) *TriageHandler {
	h := &TriageHandler{}
	// Avoid the typed-nil-into-interface trap so the `h.store == nil`
	// guards in the handlers behave correctly when no store is wired.
	if store != nil {
		h.store = store
	}
	return h
}

// validTriageStatuses mirrors the SQL CHECK on finding_triage.status and
// the UI TriageStatus enum (server/ui/src/shared/model/triage.ts).
var validTriageStatuses = map[string]bool{
	"new":            true,
	"triaging":       true,
	"confirmed":      true,
	"accepted-risk":  true,
	"false-positive": true,
}

// HandleGet returns the triage state for a finding fingerprint. Open read.
// A fingerprint with no recorded decision returns the implicit "new" state.
func (h *TriageHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")
	if !validFingerprint(fp) {
		WriteValidationError(w, "fingerprint must be a 16-character hex string")
		return
	}
	if h.store == nil {
		WriteServiceError(w, "triage store")
		return
	}

	ts, err := h.store.GetTriage(r.Context(), fp)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get triage: %w", err))
		return
	}
	if ts == nil {
		ts = &model.TriageState{Status: "new"}
	}
	WriteJSON(w, http.StatusOK, ts)
}

type triageUpdateRequest struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

// maxTriageBodySize bounds the PUT body (a tiny {status, note} JSON);
// mirrors the ingest handler's MaxBytesReader guard. maxTriageNoteLen caps
// the note so a single field cannot bloat the finding_triage table.
const (
	maxTriageBodySize = 64 << 10 // 64 KB
	maxTriageNoteLen  = 4096
)

// HandleSet records (or updates) the triage decision for a fingerprint.
// Gated by OriginGuard (mutating endpoint).
func (h *TriageHandler) HandleSet(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")
	if !validFingerprint(fp) {
		WriteValidationError(w, "fingerprint must be a 16-character hex string")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxTriageBodySize)
	var req triageUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteValidationError(w, "invalid JSON: "+err.Error())
		return
	}
	if !validTriageStatuses[req.Status] {
		WriteValidationError(w, "invalid status; must be one of: new, triaging, confirmed, accepted-risk, false-positive")
		return
	}
	if len(req.Note) > maxTriageNoteLen {
		WriteValidationError(w, "note exceeds 4096 characters")
		return
	}
	if h.store == nil {
		WriteServiceError(w, "triage store")
		return
	}

	ts, err := h.store.UpsertTriage(r.Context(), fp, req.Status, req.Note)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("upsert triage: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, ts)
}

// validFingerprint reports whether s is a 16-character lowercase-hex
// finding fingerprint (the form produced by analysis.findingFingerprint).
func validFingerprint(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"
)

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

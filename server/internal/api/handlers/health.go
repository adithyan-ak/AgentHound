package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/jackc/pgx/v5/pgxpool"
)

type HealthHandler struct {
	reader *graph.Reader
	pgPool *pgxpool.Pool
}

func NewHealthHandler(reader *graph.Reader, pgPool *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{reader: reader, pgPool: pgPool}
}

func (h *HealthHandler) Handle(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp := map[string]string{"status": "ok"}
	statusCode := http.StatusOK

	if err := h.reader.Ping(ctx); err != nil {
		slog.Error("neo4j health check failed", "error", err)
		resp["neo4j"] = "unavailable"
		resp["status"] = "degraded"
		statusCode = http.StatusServiceUnavailable
	} else {
		resp["neo4j"] = "ok"
	}

	if err := h.pgPool.Ping(ctx); err != nil {
		slog.Error("postgres health check failed", "error", err)
		resp["postgres"] = "unavailable"
		resp["status"] = "degraded"
		statusCode = http.StatusServiceUnavailable
	} else {
		resp["postgres"] = "ok"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

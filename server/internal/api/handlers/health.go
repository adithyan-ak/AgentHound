package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/jackc/pgx/v5/pgxpool"
)

const healthCheckTimeout = 5 * time.Second

type healthPinger interface {
	Ping(context.Context) error
}

type HealthHandler struct {
	reader  healthPinger
	pgPool  healthPinger
	timeout time.Duration
}

func NewHealthHandler(reader *graph.Reader, pgPool *pgxpool.Pool) *HealthHandler {
	handler := &HealthHandler{timeout: healthCheckTimeout}
	if reader != nil {
		handler.reader = reader
	}
	if pgPool != nil {
		handler.pgPool = pgPool
	}
	return handler
}

func (h *HealthHandler) Handle(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	resp := map[string]string{"status": "ok"}
	statusCode := http.StatusOK

	type result struct {
		dependency string
		err        error
	}
	results := make(chan result, 2)
	probe := func(dependency string, pinger healthPinger) {
		if pinger == nil {
			results <- result{
				dependency: dependency,
				err:        errors.New("dependency is not configured"),
			}
			return
		}
		results <- result{dependency: dependency, err: pinger.Ping(ctx)}
	}
	go probe("neo4j", h.reader)
	go probe("postgres", h.pgPool)

	for range 2 {
		check := <-results
		if check.err != nil {
			slog.Error(check.dependency+" health check failed", "error", check.err)
			resp[check.dependency] = "unavailable"
			resp["status"] = "degraded"
			statusCode = http.StatusServiceUnavailable
		} else {
			resp[check.dependency] = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

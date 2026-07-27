package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type healthPingerFunc func(context.Context) error

func (f healthPingerFunc) Ping(ctx context.Context) error {
	return f(ctx)
}

func TestHealthHandlerProbesDependenciesConcurrently(t *testing.T) {
	postgresStarted := make(chan struct{})
	handler := &HealthHandler{
		reader: healthPingerFunc(func(ctx context.Context) error {
			select {
			case <-postgresStarted:
				return errors.New("neo4j unavailable")
			case <-ctx.Done():
				return ctx.Err()
			}
		}),
		pgPool: healthPingerFunc(func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				close(postgresStarted)
				return nil
			}
		}),
		timeout: 100 * time.Millisecond,
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.Handle(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	var response map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if response["status"] != "degraded" ||
		response["neo4j"] != "unavailable" ||
		response["postgres"] != "ok" {
		t.Fatalf("health response = %v", response)
	}
}

func TestHealthHandlerReportsMissingDependencies(t *testing.T) {
	handler := NewHealthHandler(nil, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.Handle(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	var response map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if response["status"] != "degraded" ||
		response["neo4j"] != "unavailable" ||
		response["postgres"] != "unavailable" {
		t.Fatalf("health response = %v", response)
	}
}

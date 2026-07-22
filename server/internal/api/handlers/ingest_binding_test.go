package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/server/internal/binding"
	serveringest "github.com/adithyan-ak/agenthound/server/internal/ingest"
)

type rejectingStorageVerification struct{ err error }

func (a rejectingStorageVerification) Verify(context.Context) error {
	return a.err
}

func TestIngestBindingErrorsHaveStableHTTPContracts(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantSecret string
	}{
		{
			name:       "storage verification unavailable",
			err:        &binding.StorageError{Message: "PostgreSQL marker read failed", Cause: errors.New("password=do-not-leak")},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "STORAGE_BINDING_UNAVAILABLE",
			wantSecret: "password=do-not-leak",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := common.NewIngestData("scan", "binding-http-contract")
			body, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			pipeline := serveringest.NewPipeline(nil, nil, nil, nil, rejectingStorageVerification{err: test.err})
			handler := NewIngestHandler(pipeline)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body))
			recorder := httptest.NewRecorder()

			handler.Handle(recorder, req)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), test.wantCode) {
				t.Fatalf("body = %s, want code %s", recorder.Body.String(), test.wantCode)
			}
			if test.wantSecret != "" && strings.Contains(recorder.Body.String(), test.wantSecret) {
				t.Fatalf("storage error leaked internal cause: %s", recorder.Body.String())
			}
		})
	}
}

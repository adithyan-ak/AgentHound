package jupyterfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const jupyterStatusBody = `{"started":"2026-04-01T12:00:00.000000Z","last_activity":"2026-04-01T12:34:56.000000Z","connections":3,"kernels":2}`

func TestFingerprintRequiresPublicAPICandidate(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{
			name:        "canonical",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        `{"version":"2.20.0"}`,
		},
		{
			name:        "authentication denial",
			status:      http.StatusForbidden,
			contentType: "application/json",
			body:        `{}`,
		},
		{
			name:        "malformed JSON",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        `{`,
		},
		{
			name:        "missing version",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        `{"name":"not-jupyter"}`,
		},
		{
			name:        "non-JSON response",
			status:      http.StatusOK,
			contentType: "text/html",
			body:        `{"version":"2.20.0"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusProbes := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api":
					w.Header().Set("Content-Type", tt.contentType)
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
				case "/api/status":
					statusProbes++
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(jupyterStatusBody))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			res := fingerprintTarget(t, srv)
			if tt.name == "canonical" {
				if !res.Matched {
					t.Fatal("canonical public /api evidence should permit the status decision")
				}
				if statusProbes != 1 {
					t.Fatalf("status probes = %d, want 1", statusProbes)
				}
				return
			}
			if res.Matched {
				t.Fatal("status evidence alone must not identify Jupyter Server")
			}
			if statusProbes != 0 {
				t.Fatalf("status probes = %d, want 0 after invalid /api candidate", statusProbes)
			}
		})
	}
}

func TestFingerprintStatusDecision(t *testing.T) {
	tests := []struct {
		name             string
		status           int
		contentType      string
		body             string
		wantMatch        bool
		wantStatusAccess string
		wantAnonymous    bool
	}{
		{
			name:             "canonical anonymous success",
			status:           http.StatusOK,
			contentType:      "application/json",
			body:             jupyterStatusBody,
			wantMatch:        true,
			wantStatusAccess: "anonymous",
			wantAnonymous:    true,
		},
		{
			name:             "unauthorized",
			status:           http.StatusUnauthorized,
			contentType:      "text/html",
			body:             "login required",
			wantMatch:        true,
			wantStatusAccess: "denied",
		},
		{
			name:             "forbidden",
			status:           http.StatusForbidden,
			contentType:      "application/json",
			body:             `{"message":"forbidden"}`,
			wantMatch:        true,
			wantStatusAccess: "denied",
		},
		{
			name:        "missing status route",
			status:      http.StatusNotFound,
			contentType: "text/plain",
			body:        "not found",
		},
		{
			name:        "malformed status",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        `{"started":"2026-04-01T12:00:00Z"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"version":"2.20.0"}`))
				case "/api/status":
					w.Header().Set("Content-Type", tt.contentType)
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			res := fingerprintTarget(t, srv)
			if res.Matched != tt.wantMatch {
				t.Fatalf("Matched = %v, want %v", res.Matched, tt.wantMatch)
			}
			if !tt.wantMatch {
				return
			}
			if res.ServiceKind != "jupyter" {
				t.Fatalf("ServiceKind = %q, want jupyter", res.ServiceKind)
			}
			if res.Version != "2.20.0" {
				t.Fatalf("Version = %q, want 2.20.0", res.Version)
			}
			if res.AuthMethod != "unknown" {
				t.Fatalf("AuthMethod = %q, want unknown", res.AuthMethod)
			}
			if res.IngestData == nil || len(res.IngestData.Graph.Nodes) != 1 {
				t.Fatalf("expected 1 ingest node, got %+v", res.IngestData)
			}
			node := res.IngestData.Graph.Nodes[0]
			if len(node.Kinds) != 2 ||
				node.Kinds[0] != "JupyterServer" ||
				node.Kinds[1] != "AIService" {
				t.Fatalf("node.Kinds = %v, want [JupyterServer AIService]", node.Kinds)
			}
			if node.Properties["status_access"] != tt.wantStatusAccess {
				t.Fatalf("status_access = %v, want %q", node.Properties["status_access"], tt.wantStatusAccess)
			}
			if node.Properties["status_anonymous_access"] != tt.wantAnonymous {
				t.Fatalf(
					"status_anonymous_access = %v, want %v",
					node.Properties["status_anonymous_access"],
					tt.wantAnonymous,
				)
			}
			if node.Properties["fingerprint_detector_id"] != "jupyter-http-native" ||
				node.Properties["fingerprint_detector_version"] != 1 ||
				node.Properties["fingerprint_detector_source"] != "builtin" {
				t.Fatalf("native detector provenance = %+v", node.Properties)
			}
			for _, protectedConclusion := range []string{
				"auth_method",
				"auth_required",
				"auth_evidence",
				"is_anonymous_loot",
			} {
				if _, exists := node.Properties[protectedConclusion]; exists {
					t.Errorf(
						"status probe emitted protected-operation conclusion %q: %+v",
						protectedConclusion,
						node.Properties,
					)
				}
			}
		})
	}
}

func TestFingerprintUsesJupyterBundleOverrideAndRecordsProvenance(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jupyter.yaml"), []byte(`
id: jupyter
name: Jupyter runtime override
version: 9
service_kind: jupyter
probes:
  - method: GET
    path: /bundle-jupyter
    matchers:
      - type: http_status
        status_code: 200
    captures:
      version: $.version
emit:
  node_kinds: [JupyterServer, AIService]
  properties:
    objectid: spoofed-object
    endpoint: https://spoofed.invalid
    service_kind: spoofed
    fingerprint_detector_id: spoofed-detector
    fingerprint_detector_version: "999"
    fingerprint_detector_source: spoofed-source
    version: "{capture:version}"
`), 0o600); err != nil {
		t.Fatalf("write Jupyter override: %v", err)
	}
	rules.SetBundleOverridePath(dir)
	t.Cleanup(func() { rules.SetBundleOverridePath("") })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/bundle-jupyter" {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"9.9.9"}`))
	}))
	t.Cleanup(server.Close)

	result := fingerprintTarget(t, server)
	if !result.Matched || result.Version != "9.9.9" {
		t.Fatalf("bundle Jupyter result = %+v", result)
	}
	node := result.IngestData.Graph.Nodes[0]
	if node.Properties["fingerprint_detector_id"] != "jupyter" ||
		node.Properties["fingerprint_detector_version"] != 9 ||
		node.Properties["fingerprint_detector_source"] != "bundle" {
		t.Fatalf("bundle detector provenance = %+v", node.Properties)
	}
	if node.Properties["objectid"] != node.ID ||
		node.Properties["endpoint"] != server.URL ||
		node.Properties["service_kind"] != "jupyter" {
		t.Fatalf("bundle overwrote reserved Jupyter identity: %+v", node.Properties)
	}
}

func TestFingerprintRejectsWrongKindJupyterOverrideWithoutNativeFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jupyter.yaml"), []byte(`
id: jupyter
name: Misdirected Jupyter override
version: 2
service_kind: ollama
probes:
  - method: GET
    path: /wrong-kind
    matchers:
      - type: http_status
        status_code: 200
emit:
  node_kinds: [JupyterServer, AIService]
`), 0o600); err != nil {
		t.Fatalf("write wrong-kind Jupyter override: %v", err)
	}
	rules.SetBundleOverridePath(dir)
	t.Cleanup(func() { rules.SetBundleOverridePath("") })

	fingerprinter, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = fingerprinter.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: "127.0.0.1:8888",
	})
	if err == nil || !strings.Contains(err.Error(), "service_kind") {
		t.Fatalf("wrong-kind override error = %v", err)
	}
}

func TestValidateBundleOverrideRequiresExactNodeKindTuple(t *testing.T) {
	tests := []struct {
		name    string
		kinds   []string
		wantErr bool
	}{
		{name: "exact", kinds: []string{"JupyterServer", "AIService"}},
		{name: "wrong order", kinds: []string{"AIService", "JupyterServer"}, wantErr: true},
		{name: "duplicate", kinds: []string{"JupyterServer", "AIService", "AIService"}, wantErr: true},
		{name: "extra concrete kind", kinds: []string{"JupyterServer", "AIService", "Host"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := rules.FingerprintRule{
				ID:          BundleOverrideID,
				Name:        "Jupyter override",
				Version:     1,
				ServiceKind: "jupyter",
				Probes: []rules.FingerprintProbe{{
					Method: "GET",
					Path:   "/api",
					Matchers: []rules.FingerprintMatch{{
						Type:       "http_status",
						StatusCode: http.StatusOK,
					}},
				}},
				Emit: rules.FingerprintEmit{NodeKinds: tt.kinds},
			}

			err := ValidateBundleOverride(rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateBundleOverride(%v) error = %v, wantErr %v", tt.kinds, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "exactly [JupyterServer AIService]") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestFingerprintExcludesKernelGatewayCollision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"3.0.1"}`))
		case "/api/status":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	if res := fingerprintTarget(t, srv); res.Matched {
		t.Fatal("Kernel Gateway public /api collision was identified as JupyterServer")
	}
}

func fingerprintTarget(t *testing.T, srv *httptest.Server) *action.FingerprintResult {
	t.Helper()
	fingerprinter, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := fingerprinter.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	return result
}

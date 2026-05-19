package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunFingerprint_OllamaHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"0.5.1"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	rule := FingerprintRule{
		ID:          "ollama",
		Name:        "Ollama",
		ServiceKind: "ollama",
		Probes: []FingerprintProbe{
			{
				Method: "GET",
				Path:   "/api/version",
				Matchers: []FingerprintMatch{
					{Type: "http_status", StatusCode: 200},
					{Type: "json_path", Path: "$.version", Regex: `^\d+\.\d+\.\d+$`},
				},
				Captures: map[string]string{"version": "$.version"},
			},
		},
		Emit: FingerprintEmit{
			NodeKinds: []string{"OllamaInstance", "AIService"},
			Properties: map[string]string{
				"version":     "{capture:version}",
				"auth_method": "none",
			},
		},
	}

	res, err := RunFingerprint(context.Background(),
		DefaultFingerprintHTTPClient(2*time.Second), srv.URL, rule)
	if err != nil {
		t.Fatalf("RunFingerprint: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected match")
	}
	if got := res.Properties["version"]; got != "0.5.1" {
		t.Errorf("properties.version = %q, want 0.5.1", got)
	}
	if got := res.Properties["auth_method"]; got != "none" {
		t.Errorf("properties.auth_method = %q, want none", got)
	}
	if len(res.NodeKinds) != 2 || res.NodeKinds[0] != "OllamaInstance" || res.NodeKinds[1] != "AIService" {
		t.Errorf("NodeKinds = %v, want [OllamaInstance AIService]", res.NodeKinds)
	}
}

func TestRunFingerprint_NoMatch_WrongStatusOrShape(t *testing.T) {
	t.Run("404 fails http_status matcher", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
		}))
		defer srv.Close()
		rule := minimalOllamaRule()
		res, err := RunFingerprint(context.Background(),
			DefaultFingerprintHTTPClient(2*time.Second), srv.URL, rule)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if res.Matched {
			t.Error("expected no match on 404")
		}
	})

	t.Run("malformed JSON fails json_path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`not-json`))
		}))
		defer srv.Close()
		rule := minimalOllamaRule()
		res, err := RunFingerprint(context.Background(),
			DefaultFingerprintHTTPClient(2*time.Second), srv.URL, rule)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if res.Matched {
			t.Error("expected no match on malformed JSON")
		}
	})

	t.Run("network error returns no-match no-error", func(t *testing.T) {
		// Use a port we know is closed.
		rule := minimalOllamaRule()
		res, err := RunFingerprint(context.Background(),
			DefaultFingerprintHTTPClient(500*time.Millisecond),
			"http://127.0.0.1:1", rule)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if res.Matched {
			t.Error("expected no match on network failure")
		}
	})
}

func TestRunFingerprint_BodyMatchers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("I'm alive!"))
	}))
	defer srv.Close()

	tests := []struct {
		name string
		m    FingerprintMatch
		want bool
	}{
		{"body_equals match", FingerprintMatch{Type: "body_equals", Value: "I'm alive!"}, true},
		{"body_equals no-match", FingerprintMatch{Type: "body_equals", Value: "different"}, false},
		{"body_contains match", FingerprintMatch{Type: "body_contains", Value: "alive"}, true},
		{"body_contains case-insensitive", FingerprintMatch{Type: "body_contains", Value: "ALIVE", CaseInsensitive: true}, true},
		{"body_regex match", FingerprintMatch{Type: "body_regex", Pattern: `alive!?`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := FingerprintRule{
				ID: "test", Name: "test", ServiceKind: "test",
				Probes: []FingerprintProbe{{Method: "GET", Path: "/x",
					Matchers: []FingerprintMatch{
						{Type: "http_status", StatusCode: 200},
						tt.m,
					}}},
				Emit: FingerprintEmit{NodeKinds: []string{"X"}},
			}
			res, err := RunFingerprint(context.Background(),
				DefaultFingerprintHTTPClient(2*time.Second), srv.URL, rule)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if res.Matched != tt.want {
				t.Errorf("Matched = %v, want %v", res.Matched, tt.want)
			}
		})
	}
}

func TestRunFingerprint_HeaderMatcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "openresty/1.21.4.1")
		w.Header().Set("X-Custom", "qdrant-1.10.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	t.Run("header value match", func(t *testing.T) {
		rule := FingerprintRule{
			ID: "test", Name: "test", ServiceKind: "test",
			Probes: []FingerprintProbe{{Method: "GET", Path: "/x",
				Matchers: []FingerprintMatch{
					{Type: "http_status", StatusCode: 200},
					{Type: "http_header", Name: "X-Custom", Value: "qdrant"},
				}}},
			Emit: FingerprintEmit{NodeKinds: []string{"X"}},
		}
		res, err := RunFingerprint(context.Background(),
			DefaultFingerprintHTTPClient(2*time.Second), srv.URL, rule)
		if err != nil || !res.Matched {
			t.Errorf("res=%+v err=%v", res, err)
		}
	})

	t.Run("header pattern match", func(t *testing.T) {
		rule := FingerprintRule{
			ID: "test", Name: "test", ServiceKind: "test",
			Probes: []FingerprintProbe{{Method: "GET", Path: "/x",
				Matchers: []FingerprintMatch{
					{Type: "http_status", StatusCode: 200},
					{Type: "http_header", Name: "Server", Pattern: `^openresty/`},
				}}},
			Emit: FingerprintEmit{NodeKinds: []string{"X"}},
		}
		res, err := RunFingerprint(context.Background(),
			DefaultFingerprintHTTPClient(2*time.Second), srv.URL, rule)
		if err != nil || !res.Matched {
			t.Errorf("res=%+v err=%v", res, err)
		}
	})
}

func TestStatusInRange(t *testing.T) {
	tests := []struct {
		code int
		spec string
		want bool
	}{
		{200, "2xx", true},
		{299, "2xx", true},
		{300, "2xx", false},
		{200, "200-299", true},
		{299, "200-299", true},
		{404, "200-299", false},
		{200, "200", true},
		{201, "200", false},
		{200, "", false}, // empty range never matches
	}
	for _, tt := range tests {
		if got := statusInRange(tt.code, tt.spec); got != tt.want {
			t.Errorf("statusInRange(%d, %q) = %v, want %v", tt.code, tt.spec, got, tt.want)
		}
	}
}

func TestJSONPathExtract(t *testing.T) {
	body := []byte(`{"version":"0.5.1","capabilities":{"tasks":true},"count":42,"valid":true,"nothing":null}`)
	tests := []struct {
		path   string
		want   string
		exists bool
	}{
		{"$.version", "0.5.1", true},
		{"$.capabilities.tasks", "true", true},
		{"$.count", "42", true},
		{"$.valid", "true", true},
		{"$.nothing", "", true}, // null exists but stringifies to ""
		{"$.missing", "", false},
		{"$.capabilities.missing", "", false},
		{"version", "", false}, // malformed: no $
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := jsonPathExtract(body, tt.path)
			if ok != tt.exists {
				t.Errorf("exists = %v, want %v", ok, tt.exists)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("invalid json returns no-match", func(t *testing.T) {
		_, ok := jsonPathExtract([]byte(`not-json`), "$.x")
		if ok {
			t.Error("expected false for invalid json")
		}
	})
}

func TestValidateFingerprint(t *testing.T) {
	good := FingerprintRule{
		ID: "ollama", Name: "Ollama", ServiceKind: "ollama",
		Probes: []FingerprintProbe{{Method: "GET", Path: "/api/version",
			Matchers: []FingerprintMatch{{Type: "http_status", StatusCode: 200}}}},
		Emit: FingerprintEmit{NodeKinds: []string{"OllamaInstance"}},
	}
	if errs := ValidateFingerprint(good); len(errs) > 0 {
		t.Errorf("good rule rejected: %v", errs)
	}

	tests := []struct {
		name   string
		mutate func(*FingerprintRule)
		field  string
	}{
		{"empty id", func(r *FingerprintRule) { r.ID = "" }, "id"},
		{"empty name", func(r *FingerprintRule) { r.Name = "" }, "name"},
		{"no probes", func(r *FingerprintRule) { r.Probes = nil }, "probes"},
		{"POST method", func(r *FingerprintRule) { r.Probes[0].Method = "POST" }, "method"},
		{"missing path", func(r *FingerprintRule) { r.Probes[0].Path = "" }, "path"},
		{"no matchers", func(r *FingerprintRule) { r.Probes[0].Matchers = nil }, "matchers"},
		{"unknown matcher type", func(r *FingerprintRule) {
			r.Probes[0].Matchers = []FingerprintMatch{{Type: "weird"}}
		}, "type"},
		{"json_path no path", func(r *FingerprintRule) {
			r.Probes[0].Matchers = []FingerprintMatch{{Type: "json_path", Equals: "x"}}
		}, "path"},
		{"empty node_kinds", func(r *FingerprintRule) { r.Emit.NodeKinds = nil }, "node_kinds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			r.Probes = []FingerprintProbe{{
				Method:   good.Probes[0].Method,
				Path:     good.Probes[0].Path,
				Matchers: append([]FingerprintMatch{}, good.Probes[0].Matchers...),
			}}
			tt.mutate(&r)
			errs := ValidateFingerprint(r)
			if len(errs) == 0 {
				t.Fatal("expected validation error")
			}
			found := false
			for _, e := range errs {
				if strings.Contains(e.Field, tt.field) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error field containing %q, got %v", tt.field, errs)
			}
		})
	}
}

func minimalOllamaRule() FingerprintRule {
	return FingerprintRule{
		ID: "ollama", Name: "Ollama", ServiceKind: "ollama",
		Probes: []FingerprintProbe{{Method: "GET", Path: "/api/version",
			Matchers: []FingerprintMatch{
				{Type: "http_status", StatusCode: 200},
				{Type: "json_path", Path: "$.version", Regex: `^\d+\.\d+\.\d+$`},
			}}},
		Emit: FingerprintEmit{NodeKinds: []string{"OllamaInstance", "AIService"}},
	}
}

func TestLoadFingerprints_EmbeddedRulesValid(t *testing.T) {
	rules, err := LoadFingerprints()
	if err != nil {
		t.Fatalf("LoadFingerprints: %v", err)
	}
	if len(rules) < 8 {
		t.Errorf("expected at least 8 embedded fingerprint rules, got %d", len(rules))
	}
	wantKinds := []string{"ollama", "litellm", "vllm", "openwebui", "jupyter", "qdrant", "mlflow", "langserve"}
	found := make(map[string]bool)
	for _, r := range rules {
		found[r.ServiceKind] = true
	}
	for _, k := range wantKinds {
		if !found[k] {
			t.Errorf("embedded rule set missing service_kind %q", k)
		}
	}
}

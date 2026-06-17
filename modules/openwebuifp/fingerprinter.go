// Package openwebuifp implements the v0.3 Open WebUI fingerprinter module.
//
// Open WebUI is the most-deployed self-hosted ChatGPT-style frontend; it
// proxies requests to a backend Ollama (or any OpenAI-compatible API). The
// /api/version probe identifies the service; a SECOND probe to /api/config
// captures the configured backend URL. When the second probe lands, this
// module emits an :EXPOSES edge from the OpenWebUIInstance to a
// (possibly-not-yet-known) OllamaInstance node — making this the FIRST
// emitter of EXPOSES in the codebase.
//
// The writer's MERGE-by-objectid semantics handle the case where the
// target Ollama node doesn't yet exist: a placeholder node is created on
// the first :EXPOSES write, and a later Ollama fingerprint MERGE-merges
// properties onto it.
package openwebuifp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const DefaultPort = 3000

const DefaultProbeTimeout = 5 * time.Second

type Fingerprinter struct {
	rule *rules.FingerprintRule
}

func New() (*Fingerprinter, error) {
	all, err := rules.LoadFingerprints()
	if err != nil {
		return nil, fmt.Errorf("load fingerprint rules: %w", err)
	}
	for _, r := range all {
		if r.ServiceKind == "openwebui" {
			rule := r
			if errs := rules.ValidateFingerprint(rule); len(errs) > 0 {
				return nil, fmt.Errorf("openwebui rule invalid: %v", errs)
			}
			return &Fingerprinter{rule: &rule}, nil
		}
	}
	return nil, errors.New("openwebui fingerprint rule not found in builtin set")
}

func (f *Fingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	if f.rule == nil {
		return nil, errors.New("openwebui fingerprinter: rule not loaded")
	}
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")

	client := rules.DefaultFingerprintHTTPClient(DefaultProbeTimeout)
	res, err := rules.RunFingerprint(ctx, client, baseURL, *f.rule)
	if err != nil {
		slog.Debug("openwebui fingerprint probe error",
			"target", t.Address, "error", err)
		return &action.FingerprintResult{Matched: false}, nil
	}
	// The /api/config probe is conjunctive in v0.2 RunFingerprint — if
	// /api/config returns non-200, RunFingerprint reports Matched=false
	// even though the /api/version probe matched. Re-probe /api/version
	// alone to disambiguate (Open WebUI with a locked /api/config is
	// still Open WebUI). The single-probe rule is constructed inline so
	// we do not need a second YAML.
	if !res.Matched {
		fallback := *f.rule
		if len(fallback.Probes) > 0 {
			fallback.Probes = []rules.FingerprintProbe{fallback.Probes[0]}
		}
		res2, err2 := rules.RunFingerprint(ctx, client, baseURL, fallback)
		if err2 != nil || res2 == nil || !res2.Matched {
			return &action.FingerprintResult{Matched: false}, nil
		}
		res = res2
	}

	endpoint := baseURL
	objectID := ingest.ComputeNodeID("OpenWebUIInstance", endpoint)

	props := map[string]any{
		"objectid":       objectID,
		"name":           host,
		"endpoint":       endpoint,
		"discovered_via": "network_scan",
		"service_kind":   "openwebui",
	}
	for k, v := range res.Properties {
		// Don't promote an unresolved capture placeholder onto the node.
		if strings.Contains(v, "{capture:") {
			continue
		}
		props[k] = v
	}
	if _, ok := props["auth_method"]; !ok {
		props["auth_method"] = "none"
	}

	out := &ingest.IngestData{
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{{
				ID:         objectID,
				Kinds:      append([]string{}, res.NodeKinds...),
				Properties: props,
			}},
		},
	}

	// EXPOSES edge: when /api/config gave us an Ollama backend URL,
	// emit a placeholder OllamaInstance node + the edge. The writer
	// MERGE-by-objectid pattern means a later `agenthound scan` against
	// that Ollama host will fold its real properties onto this same
	// node id without duplicating.
	if backendURL := strings.TrimSpace(res.Captures["ollama_backend_url"]); backendURL != "" {
		canon := canonicalizeBackend(backendURL)
		if canon != "" {
			ollamaID := ingest.ComputeNodeID("OllamaInstance", canon)
			out.Graph.Nodes = append(out.Graph.Nodes, ingest.Node{
				ID:    ollamaID,
				Kinds: []string{"OllamaInstance", "AIService"},
				Properties: map[string]any{
					"objectid":       ollamaID,
					"endpoint":       canon,
					"discovered_via": "openwebui_config",
					"service_kind":   "ollama",
					"auth_method":    "none",
				},
			})
			out.Graph.Edges = append(out.Graph.Edges, ingest.Edge{
				Source:     objectID,
				Target:     ollamaID,
				Kind:       "EXPOSES",
				SourceKind: "OpenWebUIInstance",
				TargetKind: "OllamaInstance",
				Properties: map[string]any{
					"discovered_via": "openwebui_api_config",
					"evidence":       backendURL,
				},
			})
		}
	}

	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: "openwebui",
		Version:     res.Properties["version"],
		AuthMethod:  res.Properties["auth_method"],
		IngestData:  out,
		Properties:  res.Properties,
	}, nil
}

// canonicalizeBackend normalizes a captured backend URL to "scheme://host:port"
// (no path, no query). Returns empty when the input is unparseable so the
// caller skips the EXPOSES edge rather than emitting a junk endpoint.
func canonicalizeBackend(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Open WebUI sometimes stores the backend without a scheme. Default
	// to http:// so url.Parse succeeds.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		// Default Ollama port — matches what ollamafp uses for objectid.
		port = "11434"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

var _ action.Fingerprinter = (*Fingerprinter)(nil)

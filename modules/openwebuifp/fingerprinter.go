// Package openwebuifp implements the v0.3 Open WebUI fingerprinter module.
//
// Open WebUI is the most-deployed self-hosted ChatGPT-style frontend; it
// proxies requests to a backend Ollama (or any OpenAI-compatible API). The
// /api/version probe identifies the service; a SECOND probe to /api/config
// confirms the response body carries {"name": "Open WebUI", ...} as a
// belt-and-braces guard.
//
// This module no longer emits an EXPOSES edge from OpenWebUIInstance to
// OllamaInstance. The old edge was fenced on capturing $.ollama.base_url
// from /api/config, but that field is verified absent from Open WebUI's
// get_app_config response on every tag from v0.1.111 through v0.9.6 (and
// main), so the edge never fired in practice. The authenticated
// openwebuiloot Looter emits the EXPOSES edge from the admin-gated
// /ollama/config endpoint (which does return OLLAMA_BASE_URLS).
package openwebuifp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
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
		return &action.FingerprintResult{Matched: false}, err
	}
	if !res.Matched {
		return &action.FingerprintResult{Matched: false}, nil
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
	auth := common.AssessAuth(fmt.Sprint(props["auth_method"]))
	props["auth_method"] = string(auth.Method)
	props["auth_assurance"] = string(auth.Assurance)
	props["auth_evidence"] = common.AuthEvidenceAnonymousProbeSucceeded
	props["probe_status"] = string(common.VerificationVerified)
	props["last_verified_at"] = time.Now().UTC().Format(time.RFC3339)

	out := &ingest.IngestData{
		Graph: ingest.GraphData{
			Nodes: []ingest.Node{{
				ID:         objectID,
				Kinds:      append([]string{}, res.NodeKinds...),
				Properties: props,
			}},
		},
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

var _ action.Fingerprinter = (*Fingerprinter)(nil)

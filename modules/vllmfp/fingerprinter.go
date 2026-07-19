// Package vllmfp implements the v0.3 vLLM fingerprinter module.
//
// vLLM is a high-throughput LLM inference server speaking the OpenAI-compatible
// API. Its service-specific /version endpoint is the canonical fingerprint.
// The probe semantics live in
// sdk/rules/builtin/fingerprints/vllm.yaml; this package is just the
// dispatcher that loads the rule and runs it via sdk/rules.RunFingerprint.
package vllmfp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

// DefaultPort is vLLM's well-known port (its default --host 0.0.0.0 --port
// 8000 launch line). The scanner already enumerates 8000 in the AI-service
// port set; this constant is used only when Target.Address is a bare host.
const DefaultPort = 8000

// DefaultProbeTimeout caps a single fingerprint dispatch. /version on a
// vLLM box returns within milliseconds; 5s is generous and matches the rest
// of the v0.2 fingerprinters.
const DefaultProbeTimeout = 5 * time.Second

// Fingerprinter is the registered module.
type Fingerprinter struct {
	rule *rules.FingerprintRule
}

// New loads the vLLM fingerprint rule and returns a ready-to-use
// Fingerprinter. Call from init() in register.go.
func New() (*Fingerprinter, error) {
	all, err := rules.LoadFingerprints()
	if err != nil {
		return nil, fmt.Errorf("load fingerprint rules: %w", err)
	}
	for _, r := range all {
		if r.ServiceKind == "vllm" {
			rule := r
			if errs := rules.ValidateFingerprint(rule); len(errs) > 0 {
				return nil, fmt.Errorf("vllm rule invalid: %v", errs)
			}
			return &Fingerprinter{rule: &rule}, nil
		}
	}
	return nil, errors.New("vllm fingerprint rule not found in builtin set")
}

// Fingerprint runs the vLLM probe against t.Address. See ollamafp's
// docstring for the splitHostPort + scheme override contract; this module
// follows the identical pattern for cross-fingerprinter consistency.
func (f *Fingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	if f.rule == nil {
		return nil, errors.New("vllm fingerprinter: rule not loaded")
	}
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")

	client := rules.DefaultFingerprintHTTPClient(DefaultProbeTimeout)
	res, err := rules.RunFingerprint(ctx, client, baseURL, *f.rule)
	if err != nil {
		slog.Debug("vllm fingerprint probe error",
			"target", t.Address, "error", err)
		return &action.FingerprintResult{Matched: false}, err
	}
	if !res.Matched {
		return &action.FingerprintResult{Matched: false}, nil
	}

	endpoint := baseURL
	objectID := ingest.ComputeNodeID("VLLMInstance", endpoint)

	props := map[string]any{
		"objectid":       objectID,
		"name":           host,
		"endpoint":       endpoint,
		"discovered_via": "network_scan",
		"service_kind":   "vllm",
	}
	for k, v := range res.Properties {
		props[k] = v
	}

	node := ingest.Node{
		ID:         objectID,
		Kinds:      append([]string{}, res.NodeKinds...),
		Properties: props,
	}
	out := &ingest.IngestData{
		Graph: ingest.GraphData{Nodes: []ingest.Node{node}},
	}

	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: "vllm",
		Version:     res.Properties["version"],
		AuthMethod:  res.Properties["auth_method"],
		IngestData:  out,
		Properties:  res.Properties,
	}, nil
}

var _ action.Fingerprinter = (*Fingerprinter)(nil)

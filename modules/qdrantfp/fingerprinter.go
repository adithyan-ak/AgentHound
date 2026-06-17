// Package qdrantfp implements the v0.4 Qdrant fingerprinter module.
// Probe semantics live in sdk/rules/builtin/fingerprints/qdrant.yaml.
package qdrantfp

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

const (
	DefaultPort         = 6333
	DefaultProbeTimeout = 5 * time.Second
)

type Fingerprinter struct {
	rule *rules.FingerprintRule
}

func New() (*Fingerprinter, error) {
	all, err := rules.LoadFingerprints()
	if err != nil {
		return nil, fmt.Errorf("load fingerprint rules: %w", err)
	}
	for _, r := range all {
		if r.ServiceKind == "qdrant" {
			rule := r
			if errs := rules.ValidateFingerprint(rule); len(errs) > 0 {
				return nil, fmt.Errorf("qdrant rule invalid: %v", errs)
			}
			return &Fingerprinter{rule: &rule}, nil
		}
	}
	return nil, errors.New("qdrant fingerprint rule not found in builtin set")
}

func (f *Fingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	if f.rule == nil {
		return nil, errors.New("qdrant fingerprinter: rule not loaded")
	}
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")

	client := rules.DefaultFingerprintHTTPClient(DefaultProbeTimeout)
	res, err := rules.RunFingerprint(ctx, client, baseURL, *f.rule)
	if err != nil {
		slog.Debug("qdrant fingerprint probe error", "target", t.Address, "error", err)
		return &action.FingerprintResult{Matched: false}, nil
	}
	if !res.Matched {
		return &action.FingerprintResult{Matched: false}, nil
	}

	endpoint := baseURL
	objectID := ingest.ComputeNodeID("QdrantInstance", endpoint)

	props := map[string]any{
		"objectid":       objectID,
		"name":           host,
		"endpoint":       endpoint,
		"discovered_via": "network_scan",
		"service_kind":   "qdrant",
	}
	for k, v := range res.Properties {
		props[k] = v
	}
	if _, ok := props["auth_method"]; !ok {
		props["auth_method"] = "none"
	}

	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: "qdrant",
		Version:     res.Properties["version"],
		AuthMethod:  res.Properties["auth_method"],
		IngestData: &ingest.IngestData{
			Graph: ingest.GraphData{Nodes: []ingest.Node{{
				ID: objectID, Kinds: append([]string{}, res.NodeKinds...), Properties: props,
			}}},
		},
		Properties: res.Properties,
	}, nil
}

var _ action.Fingerprinter = (*Fingerprinter)(nil)

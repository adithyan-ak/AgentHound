// Package langservefp implements the v0.4 LangServe fingerprinter.
// Probe semantics live in sdk/rules/builtin/fingerprints/langserve.yaml.
package langservefp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const (
	DefaultPort         = 8000
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
		if r.ServiceKind == "langserve" {
			rule := r
			if errs := rules.ValidateFingerprint(rule); len(errs) > 0 {
				return nil, fmt.Errorf("langserve rule invalid: %v", errs)
			}
			return &Fingerprinter{rule: &rule}, nil
		}
	}
	return nil, errors.New("langserve fingerprint rule not found in builtin set")
}

func (f *Fingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	if f.rule == nil {
		return nil, errors.New("langserve fingerprinter: rule not loaded")
	}
	host, port := splitHostPort(t.Address, DefaultPort)
	scheme := "http"
	if s, ok := t.Meta["scheme"]; ok && s != "" {
		scheme = s
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	client := rules.DefaultFingerprintHTTPClient(DefaultProbeTimeout)
	res, err := rules.RunFingerprint(ctx, client, baseURL, *f.rule)
	if err != nil {
		slog.Debug("langserve fingerprint probe error", "target", t.Address, "error", err)
		return &action.FingerprintResult{Matched: false}, nil
	}
	if !res.Matched {
		return &action.FingerprintResult{Matched: false}, nil
	}
	endpoint := baseURL
	objectID := ingest.ComputeNodeID("LangServeApp", endpoint)
	props := map[string]any{
		"objectid":       objectID,
		"name":           host,
		"endpoint":       endpoint,
		"discovered_via": "network_scan",
		"service_kind":   "langserve",
	}
	for k, v := range res.Properties {
		props[k] = v
	}
	if _, ok := props["auth_method"]; !ok {
		props["auth_method"] = "none"
	}
	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: "langserve",
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

func splitHostPort(addr string, defaultPort int) (string, int) {
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			return splitHostPort(u.Host, defaultPort)
		}
	}
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		host := addr[:i]
		var p int
		_, _ = fmt.Sscanf(addr[i+1:], "%d", &p)
		if p > 0 {
			host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
			return host, p
		}
	}
	host := strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	return host, defaultPort
}

var _ action.Fingerprinter = (*Fingerprinter)(nil)

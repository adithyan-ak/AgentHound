// Package ollamafp implements the v0.2 Ollama fingerprinter module.
// It probes a Target's Address (expected shape "host:11434") with
// GET /api/version and emits a multi-label :OllamaInstance:AIService
// node when the response matches the canonical Ollama version JSON.
//
// The probe semantics, JSON shape, captures, and node properties live
// in sdk/rules/builtin/fingerprints/ollama.yaml. This package is just
// the dispatcher that loads that YAML, locates it by service_kind, and
// runs it via sdk/rules.RunFingerprint.
package ollamafp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

// DefaultPort is Ollama's well-known port. Used to build a base URL when
// Target.Address is a bare host (no port).
const DefaultPort = 11434

// DefaultProbeTimeout caps a single fingerprint dispatch. Ollama's
// /api/version is tiny; 5 seconds is generous.
const DefaultProbeTimeout = 5 * time.Second

// Fingerprinter is the registered module. It loads the ollama.yaml
// rule once at init() and dispatches against it.
type Fingerprinter struct {
	rule *rules.FingerprintRule
}

// New loads the Ollama fingerprint rule and returns a ready-to-use
// Fingerprinter. Call from init() in register.go; callers usually
// resolve via sdk/module.GetByTarget("ollama", action.Fingerprint).
func New() (*Fingerprinter, error) {
	all, err := rules.LoadFingerprints()
	if err != nil {
		return nil, fmt.Errorf("load fingerprint rules: %w", err)
	}
	for _, r := range all {
		if r.ServiceKind == "ollama" {
			rule := r
			if errs := rules.ValidateFingerprint(rule); len(errs) > 0 {
				return nil, fmt.Errorf("ollama rule invalid: %v", errs)
			}
			return &Fingerprinter{rule: &rule}, nil
		}
	}
	return nil, errors.New("ollama fingerprint rule not found in builtin set")
}

// Fingerprint runs the Ollama probe against t.Address. The Target's
// Kind must be "host"; .Address must be either "host" or "host:port".
// When no port is present, DefaultPort (11434) is used. HTTP is the
// default scheme; tests can override by setting Target.Meta["scheme"].
//
// On a successful match the returned IngestData carries one
// :OllamaInstance:AIService node whose objectid is derived from
// (host:port) so re-fingerprinting the same endpoint merges in place.
func (f *Fingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	if f.rule == nil {
		return nil, errors.New("ollama fingerprinter: rule not loaded")
	}
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")

	client := rules.DefaultFingerprintHTTPClient(DefaultProbeTimeout)
	res, err := rules.RunFingerprint(ctx, client, baseURL, *f.rule)
	if err != nil {
		slog.Debug("ollama fingerprint probe error",
			"target", t.Address, "error", err)
		return &action.FingerprintResult{Matched: false}, nil
	}
	if !res.Matched {
		return &action.FingerprintResult{Matched: false}, nil
	}

	// Build the ingest node. ObjectID = SHA-256("OllamaInstance:host:port")
	// so re-fingerprinting the same endpoint deterministically merges.
	endpoint := baseURL
	objectID := ingest.ComputeNodeID("OllamaInstance", endpoint)

	props := map[string]any{
		"objectid":       objectID,
		"name":           host,
		"endpoint":       endpoint,
		"discovered_via": "network_scan",
		"service_kind":   "ollama",
	}
	for k, v := range res.Properties {
		props[k] = v
	}
	// Ensure the umbrella-required props are present even if the rule
	// template forgot them — defensive.
	if _, ok := props["auth_method"]; !ok {
		props["auth_method"] = "none"
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
		ServiceKind: "ollama",
		Version:     res.Properties["version"],
		AuthMethod:  res.Properties["auth_method"],
		IngestData:  out,
		Properties:  res.Properties,
	}, nil
}

// splitHostPort parses "host" or "host:port" or "scheme://host:port"
// and returns (host, port). Falls back to defaultPort when no port is
// supplied. Handles the common cases the scanner emits.
func splitHostPort(addr string, defaultPort int) (string, int) {
	addr = strings.TrimSpace(addr)
	// URL form? scan won't emit this for "host" Targets, but defensive.
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			return splitHostPort(u.Host, defaultPort)
		}
	}
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		// Crude but adequate — IPv6 literals come bracketed from the
		// scanner's hostResultToTarget path.
		host := addr[:i]
		var p int
		_, _ = fmt.Sscanf(addr[i+1:], "%d", &p)
		if p > 0 {
			// Strip IPv6 brackets if present.
			host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
			return host, p
		}
	}
	// Bare host.
	host := strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	return host, defaultPort
}

// Compile-time check.
var _ action.Fingerprinter = (*Fingerprinter)(nil)

// hostInfoFor is unused but documents the host classification we'd run if
// the fingerprinter ever needed to enforce private-only — today the
// scanner enforces this gate before our dispatch.
var _ = common.ClassifyHost

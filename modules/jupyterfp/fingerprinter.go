// Package jupyterfp identifies Jupyter Server without conflating it with
// Jupyter Kernel Gateway. Identification requires a public /api candidate plus
// either canonical /api/status JSON or an authentication denial from that
// canonical status route.
package jupyterfp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const (
	DefaultPort           = 8888
	DefaultProbeTimeout   = 5 * time.Second
	NativeDetectorID      = "jupyter-http-native"
	NativeDetectorVersion = 1
	BundleOverrideID      = "jupyter"
	maxProbeBody          = 1 << 20

	statusAccessAnonymous = "anonymous"
	statusAccessDenied    = "denied"
)

type Fingerprinter struct{}

func New() (*Fingerprinter, error) { return &Fingerprinter{}, nil }

// NativeDetectorDefinition describes the code-backed default semantics written
// to scan ruleset manifests when no Jupyter bundle override is active.
func NativeDetectorDefinition() rules.CodeDetector {
	return rules.CodeDetector{
		ID:      NativeDetectorID,
		Version: NativeDetectorVersion,
		Source:  rules.BundleSourceBuiltin,
		EffectiveMatcher: json.RawMessage(`{
  "transport": "http",
  "redirects": "rejected",
  "response_body_limit_bytes": 1048576,
  "decision": "all",
  "probes": [
    {
      "method": "GET",
      "path": "/api",
      "requires": {
        "status": 200,
        "content_type": "application/json",
        "json": {"version": "nonempty_string"}
      }
    },
    {
      "method": "GET",
      "path": "/api/status",
      "accepts": [
        {
          "status": 200,
          "content_type": "application/json",
          "json": {
            "started": "rfc3339",
            "last_activity": "rfc3339",
            "connections": "nonnegative_integer",
            "kernels": "nonnegative_integer"
          }
        },
        {
          "status_codes": [401, 403],
          "evidence": "anonymous_status_access_denied"
        }
      ]
    }
  ]
}`),
	}
}

func (f *Fingerprinter) Fingerprint(
	ctx context.Context,
	target action.Target,
) (*action.FingerprintResult, error) {
	_, host, _ := action.EndpointParts(target, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(target, DefaultPort, "http")

	override, err := runtimeOverride()
	if err != nil {
		return nil, err
	}
	if override != nil {
		return fingerprintWithRule(ctx, host, baseURL, *override)
	}

	client := common.NoRedirectClient(DefaultProbeTimeout)

	apiStatus, apiBody, apiContentType, err := probe(
		ctx,
		client,
		baseURL+"/api",
	)
	if err != nil ||
		apiStatus != http.StatusOK ||
		!isJSONContentType(apiContentType) {
		return &action.FingerprintResult{Matched: false}, nil
	}
	var candidate struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(apiBody, &candidate); err != nil ||
		strings.TrimSpace(candidate.Version) == "" {
		return &action.FingerprintResult{Matched: false}, nil
	}

	statusCode, statusBody, statusContentType, err := probe(
		ctx,
		client,
		baseURL+"/api/status",
	)
	if err != nil {
		return &action.FingerprintResult{Matched: false}, nil
	}
	statusAccess := ""
	statusAnonymous := false
	switch statusCode {
	case http.StatusOK:
		if !isJSONContentType(statusContentType) ||
			!canonicalStatusBody(statusBody) {
			return &action.FingerprintResult{Matched: false}, nil
		}
		statusAccess = statusAccessAnonymous
		statusAnonymous = true
	case http.StatusUnauthorized, http.StatusForbidden:
		// This proves only that anonymous access to /api/status was denied.
		// It does not identify token, password, proxy, or another mechanism.
		statusAccess = statusAccessDenied
	default:
		// Kernel Gateway can expose a public /api version response, but does
		// not expose Jupyter Server's canonical /api/status route.
		return &action.FingerprintResult{Matched: false}, nil
	}

	endpoint := baseURL
	objectID := ingest.ComputeNodeID("JupyterServer", endpoint)
	props := map[string]any{
		"objectid":                     objectID,
		"name":                         host,
		"endpoint":                     endpoint,
		"version":                      candidate.Version,
		"discovered_via":               "network_scan",
		"fingerprint_observed":         true,
		"fingerprint_detector_id":      NativeDetectorID,
		"fingerprint_detector_version": NativeDetectorVersion,
		"fingerprint_detector_source":  rules.BundleSourceBuiltin,
		"service_kind":                 "jupyter",
		"status_access":                statusAccess,
		"status_anonymous_access":      statusAnonymous,
	}
	node := ingest.Node{
		ID:         objectID,
		Kinds:      []string{"JupyterServer", "AIService"},
		Properties: props,
	}
	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: "jupyter",
		Version:     candidate.Version,
		AuthMethod:  string(common.AuthUnknown),
		IngestData: &ingest.IngestData{
			Graph: ingest.GraphData{Nodes: []ingest.Node{node}},
		},
		Properties: map[string]string{
			"version":       candidate.Version,
			"status_access": statusAccess,
		},
	}, nil
}

func runtimeOverride() (*rules.FingerprintRule, error) {
	fingerprints, err := rules.LoadFingerprints()
	if err != nil {
		return nil, fmt.Errorf("load Jupyter fingerprint override: %w", err)
	}
	for _, candidate := range fingerprints {
		if candidate.ID != BundleOverrideID {
			continue
		}
		if err := ValidateBundleOverride(candidate); err != nil {
			return nil, err
		}
		return &candidate, nil
	}
	return nil, nil
}

// ValidateBundleOverride enforces the Jupyter module's fixed graph identity
// contract in addition to the generic fingerprint-rule schema.
func ValidateBundleOverride(rule rules.FingerprintRule) error {
	if rule.ID != BundleOverrideID {
		return fmt.Errorf(
			"jupyter fingerprint override ID is %q, want %q",
			rule.ID,
			BundleOverrideID,
		)
	}
	if rule.ServiceKind != "jupyter" {
		return fmt.Errorf(
			"jupyter fingerprint override %q has service_kind %q, want jupyter",
			rule.ID,
			rule.ServiceKind,
		)
	}
	if validation := rules.ValidateFingerprint(rule); len(validation) > 0 {
		return fmt.Errorf(
			"jupyter fingerprint override %q is invalid: %v",
			rule.ID,
			validation,
		)
	}
	if len(rule.Emit.NodeKinds) != 2 ||
		rule.Emit.NodeKinds[0] != "JupyterServer" ||
		rule.Emit.NodeKinds[1] != "AIService" {
		return fmt.Errorf(
			"jupyter fingerprint override %q must emit node kinds exactly [JupyterServer AIService]",
			rule.ID,
		)
	}
	return nil
}

func fingerprintWithRule(
	ctx context.Context,
	host string,
	baseURL string,
	rule rules.FingerprintRule,
) (*action.FingerprintResult, error) {
	result, err := rules.RunFingerprint(
		ctx,
		rules.DefaultFingerprintHTTPClient(DefaultProbeTimeout),
		baseURL,
		rule,
	)
	if err != nil {
		return nil, fmt.Errorf("run Jupyter fingerprint override: %w", err)
	}
	if !result.Matched {
		return &action.FingerprintResult{Matched: false}, nil
	}

	endpoint := baseURL
	objectID := ingest.ComputeNodeID("JupyterServer", endpoint)
	properties := make(map[string]any, len(result.Properties)+9)
	for key, value := range result.Properties {
		properties[key] = value
	}
	properties["objectid"] = objectID
	properties["name"] = host
	properties["endpoint"] = endpoint
	properties["discovered_via"] = "network_scan"
	properties["fingerprint_observed"] = true
	properties["fingerprint_detector_id"] = rule.ID
	properties["fingerprint_detector_version"] = rule.Version
	properties["fingerprint_detector_source"] = "bundle"
	properties["service_kind"] = "jupyter"
	version := result.Properties["version"]
	authMethod := result.Properties["auth_method"]
	if authMethod == "" {
		authMethod = string(common.AuthUnknown)
	}

	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: "jupyter",
		Version:     version,
		AuthMethod:  authMethod,
		IngestData: &ingest.IngestData{Graph: ingest.GraphData{Nodes: []ingest.Node{{
			ID:         objectID,
			Kinds:      append([]string(nil), result.NodeKinds...),
			Properties: properties,
		}}}},
		Properties: result.Properties,
	}, nil
}

func probe(
	ctx context.Context,
	client *http.Client,
	endpoint string,
) (int, []byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
	if err != nil {
		return 0, nil, "", err
	}
	if len(body) > maxProbeBody {
		return 0, nil, "", fmt.Errorf(
			"probe response exceeds %d bytes",
			maxProbeBody,
		)
	}
	return resp.StatusCode, body, resp.Header.Get("Content-Type"), nil
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func canonicalStatusBody(body []byte) bool {
	var status struct {
		Started      string `json:"started"`
		LastActivity string `json:"last_activity"`
		Connections  *int64 `json:"connections"`
		Kernels      *int64 `json:"kernels"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return false
	}
	if _, err := time.Parse(time.RFC3339, status.Started); err != nil {
		return false
	}
	if _, err := time.Parse(time.RFC3339, status.LastActivity); err != nil {
		return false
	}
	return status.Connections != nil &&
		*status.Connections >= 0 &&
		status.Kernels != nil &&
		*status.Kernels >= 0
}

var _ action.Fingerprinter = (*Fingerprinter)(nil)

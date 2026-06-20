// Package openwebuiloot implements the v0.4 Open WebUI Looter.
//
// Open WebUI (default port 3000) is the most-deployed self-hosted
// ChatGPT-style frontend. It proxies to a backend Ollama or any
// OpenAI-compatible upstream, and stores per-user chats, RAG documents,
// and (admin-configured) upstream provider API keys. The Looter runs in
// two modes:
//
// ANONYMOUS (no creds): GET /api/config (unauthenticated) — folds POSTURE
// properties onto the existing :OpenWebUIInstance node: signup_enabled,
// default_user_role (if present), auth_required, and re-captures
// ollama_backend_url if present. The openwebuifp fingerprinter already
// emits the EXPOSES->OllamaInstance edge from this capture; the Looter
// only enriches node properties and does NOT duplicate that edge.
//
// AUTHENTICATED (operator supplies --api-key): GET /openai/config
// (admin-gated) — enumerates the configured upstream provider API keys
// and emits one :Credential node per non-empty key, each linked via an
// EXPOSES_CREDENTIAL edge anchored on the OpenWebUIInstance. value_hash
// is MANDATORY on every Credential; the raw value is gated behind
// opts.IncludeCredentialValues. Mirrors the Credential + EXPOSES_CREDENTIAL
// emission pattern in modules/litellmloot.
//
// Probes (GET only — Looters are read-only by contract):
//
//	GET /api/config     — anonymous posture
//	GET /openai/config  — authenticated upstream keys (--api-key only)
//
// ENDPOINT-SHAPE ASSUMPTION (needs live verification): the authenticated
// upstream-key path targets `GET /openai/config` and reads the
// `OPENAI_API_KEYS` / `OPENAI_API_BASE_URLS` arrays. This shape is
// grounded in the open-webui backend source (routers/openai.py) but has
// not been confirmed against a live instance across versions, so the
// parser is intentionally defensive (missing arrays -> zero credentials,
// not an error) and the anonymous posture mode works regardless.
package openwebuiloot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 3000
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 1000
)

// Looter is the registered module.
type Looter struct{}

// RegisterFlags satisfies module.FlagsModule. --api-key is the operator's
// Open WebUI admin token (a per-user API key or a session JWT for an
// admin account). When absent, the Looter runs anonymous posture mode
// only; the flag value flows through LootOptions.Extras["api-key"].
func (l *Looter) RegisterFlags(fs *pflag.FlagSet) {
	fs.String("api-key", "",
		"Open WebUI admin API key (or session JWT) for authenticated upstream-credential enumeration via GET /openai/config.")
}

// Loot probes Open WebUI. Anonymous mode always runs (posture props on
// the OpenWebUIInstance node). Authenticated mode runs only when an API
// key is supplied, emitting Credential nodes for configured upstream
// provider keys.
//
// opts.Extras key consumed by this Looter:
//
//	"api-key"  string — admin API key / JWT for GET /openai/config
//
// The key is also read from opts.Credentials["api_key"] as a fallback so
// the generic --credential api_key=... path works too.
func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")
	openwebuiID := ingest.ComputeNodeID("OpenWebUIInstance", baseURL)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}

	apiKey, _ := opts.Extras["api-key"].(string)
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(opts.Credentials["api_key"])
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res := &action.LootResult{IngestData: &ingest.IngestData{}}

	// Always emit the OpenWebUIInstance node so the posture properties and
	// EXPOSES_CREDENTIAL edges have a home. MERGE-by-objectid folds these
	// onto the fingerprinter's node.
	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    openwebuiID,
		Kinds: []string{"OpenWebUIInstance", "AIService"},
		Properties: map[string]any{
			"objectid":       openwebuiID,
			"endpoint":       baseURL,
			"name":           host,
			"discovered_via": "openwebui_loot",
			"service_kind":   "openwebui",
		},
	})
	res.Summary.EndpointsProbed++

	// 1. ANONYMOUS posture — GET /api/config.
	cfg, err := fetchConfig(ctx, client, baseURL)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("openwebui loot: /api/config failed",
			"endpoint", baseURL,
			"engagement_id", opts.EngagementID,
			"error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("api/config: %v", err))
		res.Summary.PartialFailures++
	} else {
		props := res.IngestData.Graph.Nodes[0].Properties
		props["signup_enabled"] = cfg.SignupEnabled
		// auth=false on Open WebUI's /api/config means the instance is
		// wide-open (no login gate). auth_required is the inverse.
		props["auth_required"] = cfg.AuthEnabled
		if cfg.DefaultUserRole != "" {
			props["default_user_role"] = cfg.DefaultUserRole
		}
		// Re-capture the Ollama backend URL if /api/config exposes it. The
		// fingerprinter already emits the EXPOSES->OllamaInstance edge from
		// this same capture, so we enrich the node property only and do NOT
		// duplicate the edge.
		if cfg.OllamaBackendURL != "" {
			props["ollama_backend_url"] = cfg.OllamaBackendURL
		}
	}

	// 2. AUTHENTICATED upstream credentials — GET /openai/config.
	if apiKey != "" {
		creds, credErr := fetchOpenAIConfig(ctx, client, baseURL, apiKey, maxItems)
		res.Summary.EndpointsProbed++
		if credErr != nil {
			slog.Warn("openwebui loot: /openai/config failed",
				"endpoint", baseURL,
				"key_prefix", redact(apiKey),
				"engagement_id", opts.EngagementID,
				"error", credErr)
			res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("openai/config: %v", credErr))
			res.Summary.PartialFailures++
		}
		for _, uc := range creds {
			credID := ingest.ComputeNodeID("Credential", baseURL, "upstream-"+uc.Name)
			cprops := map[string]any{
				"objectid":     credID,
				"type":         "apiKey",
				"name":         "upstream-" + uc.Name,
				"source":       "openwebui",
				"is_exposed":   true,
				"high_entropy": true,
				"format":       "upstream-provider",
				"value_hash":   uc.ValueHash,
			}
			if uc.Endpoint != "" {
				cprops["provider_endpoint"] = uc.Endpoint
			}
			if opts.IncludeCredentialValues && uc.Value != "" {
				cprops["value"] = uc.Value
			}
			res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
				ID:         credID,
				Kinds:      []string{"Credential"},
				Properties: cprops,
			})
			res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
				exposesCredentialEdge(openwebuiID, credID, opts.EngagementID, "openai_config", uc.Endpoint))
			res.Summary.CredentialsFound++
		}
	}

	slog.Info("openwebui loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"authenticated", apiKey != "",
		"credentials_found", res.Summary.CredentialsFound,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// configPosture is the slice of GET /api/config the Looter promotes onto
// the OpenWebUIInstance node. Fields are read defensively — a missing
// field leaves the zero value and the caller decides whether to emit it.
type configPosture struct {
	SignupEnabled    bool
	AuthEnabled      bool
	DefaultUserRole  string
	OllamaBackendURL string
}

// fetchConfig issues GET /api/config (unauthenticated). The signup and
// auth flags live under "features"; default_user_role is not exposed on
// current Open WebUI builds (left empty when absent, never fabricated).
// The ollama backend URL matches the fingerprinter's $.ollama.base_url
// capture when present.
func fetchConfig(ctx context.Context, client *http.Client, baseURL string) (configPosture, error) {
	body, err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+"/api/config", "")
	if err != nil {
		return configPosture{}, err
	}
	var raw struct {
		Features struct {
			Auth         *bool `json:"auth"`
			EnableSignup *bool `json:"enable_signup"`
		} `json:"features"`
		DefaultUserRole string `json:"default_user_role"`
		Ollama          struct {
			BaseURL string `json:"base_url"`
		} `json:"ollama"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return configPosture{}, fmt.Errorf("decode /api/config: %w", err)
	}
	var c configPosture
	if raw.Features.EnableSignup != nil {
		c.SignupEnabled = *raw.Features.EnableSignup
	}
	// auth defaults to true (gated) when the field is absent — we only
	// record auth_required=false when the instance explicitly reports it.
	c.AuthEnabled = true
	if raw.Features.Auth != nil {
		c.AuthEnabled = *raw.Features.Auth
	}
	c.DefaultUserRole = strings.TrimSpace(raw.DefaultUserRole)
	c.OllamaBackendURL = strings.TrimSpace(raw.Ollama.BaseURL)
	return c, nil
}

// upstreamCred captures one upstream provider key from GET /openai/config.
type upstreamCred struct {
	Name      string // index-derived slug (e.g. "openai-0")
	Endpoint  string // matching OPENAI_API_BASE_URLS entry
	Value     string // raw upstream key
	ValueHash string // SHA-256 over the key value
}

// fetchOpenAIConfig issues GET /openai/config with the admin API key and
// extracts configured upstream provider keys. ASSUMED SHAPE (needs live
// verification): the response carries parallel OPENAI_API_KEYS and
// OPENAI_API_BASE_URLS arrays where index i pairs a key with its base
// URL. Empty keys (Ollama upstreams typically have no key) are skipped.
// Parsing is defensive: a missing array yields zero credentials, not an
// error.
func fetchOpenAIConfig(ctx context.Context, client *http.Client, baseURL, apiKey string, maxItems int) ([]upstreamCred, error) {
	body, err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+"/openai/config", apiKey)
	if err != nil {
		return nil, err
	}
	var raw struct {
		APIKeys     []string `json:"OPENAI_API_KEYS"`
		APIBaseURLs []string `json:"OPENAI_API_BASE_URLS"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode /openai/config: %w", err)
	}
	var out []upstreamCred
	for i, key := range raw.APIKeys {
		if len(out) >= maxItems {
			break
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue // Ollama / keyless upstreams expose no secret.
		}
		uc := upstreamCred{
			Name:      "openai-" + strconv.Itoa(i),
			Value:     key,
			ValueHash: common.HashCredentialValue(key),
		}
		if i < len(raw.APIBaseURLs) {
			uc.Endpoint = strings.TrimSpace(raw.APIBaseURLs[i])
		}
		out = append(out, uc)
	}
	return out, nil
}

// exposesCredentialEdge builds an EXPOSES_CREDENTIAL edge from the
// OpenWebUIInstance to a Credential. SourceKind is AIService to match the
// kinds registry's EXPOSES_CREDENTIAL constraint (source must be
// AIService — see sdk/ingest/kinds.go).
func exposesCredentialEdge(instanceID, credID, engagementID, source, endpoint string) ingest.Edge {
	return ingest.Edge{
		Source:     instanceID,
		Target:     credID,
		Kind:       "EXPOSES_CREDENTIAL",
		SourceKind: "AIService",
		TargetKind: "Credential",
		Properties: map[string]any{
			"confidence":  1.0,
			"risk_weight": 0.1,
			"evidence": map[string]any{
				"endpoint":      endpoint,
				"source":        source,
				"engagement_id": engagementID,
			},
		},
	}
}

// getJSON does the GET-and-read dance. When apiKey is non-empty a Bearer
// header is attached (authenticated mode). 4 MiB cap matches the config
// scale of these endpoints.
func getJSON(ctx context.Context, client *http.Client, url, apiKey string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

// redact returns the first 8 characters of a secret followed by "..." so
// the operator's API key never appears in full in slog output.
func redact(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:8] + "..."
}

var _ action.Looter = (*Looter)(nil)
var _ interface {
	RegisterFlags(*pflag.FlagSet)
} = (*Looter)(nil)

// Package openwebuiloot implements the v0.4 Open WebUI Looter.
//
// Open WebUI (default port 3000) is the most-deployed self-hosted
// ChatGPT-style frontend. It proxies to a backend Ollama or any
// OpenAI-compatible upstream and stores per-user chats, RAG documents,
// and admin-configured upstream provider API keys. The Looter runs in
// two modes:
//
// ANONYMOUS (no creds): GET /api/config (unauthenticated) — folds
// POSTURE properties onto the existing :OpenWebUIInstance node:
// signup_enabled and auth_required.
//
// AUTHENTICATED (operator supplies --api-key): four admin-gated probes
// enumerate configured upstream provider API keys and emit one
// :Credential per key, each linked via an EXPOSES_CREDENTIAL edge:
//
//	GET /openai/config              — OPENAI_API_KEYS[] + OPENAI_API_BASE_URLS[]
//	GET /ollama/config              — OLLAMA_BASE_URLS[] + OLLAMA_API_CONFIGS{key}
//	GET /api/v1/retrieval/config    — RAG / OCR / websearch keys (recursive walker)
//	GET /api/v1/retrieval/embedding — nested openai_config.key / ollama_config.key / ...
//
// The Open WebUI upstream field name is `key` (per
// backend/open_webui/routers/ollama.py:189-192 `get_api_key`); the
// probes decode `key` primarily and fall back to a legacy `api_key`
// field for older/forked instances. OLLAMA_API_CONFIGS may be keyed by
// string index ("0", "1", …) OR by the full base URL — both lookups
// are attempted.
//
// The retrieval walker is recursive because Open WebUI's /api/v1/retrieval/
// endpoints nest secrets one level deep (openai_config.key,
// ollama_config.key, azure_openai_config.key at
// backend/open_webui/routers/retrieval.py:445-457) alongside flat
// UPPER_SNAKE fields (RAG_EXTERNAL_RERANKER_API_KEY, PADDLEOCR_VL_TOKEN,
// BING_SEARCH_V7_SUBSCRIPTION_KEY, YACY_PASSWORD, SOUGOU_API_SK). A
// flat suffix walker misses the nested case; the recursive walker
// matches on KEY/TOKEN/PASSWORD/SECRET/SUBSCRIPTION/_SK suffixes
// case-insensitively, with negative filters for ENGINE/MODEL/URL/HOST
// noise.
//
// Probes (GET only — Looters are read-only by contract):
//
//	GET /api/config                — anonymous posture
//	GET /openai/config             — authenticated upstream OpenAI keys
//	GET /ollama/config             — authenticated Ollama upstream keys
//	GET /api/v1/retrieval/config   — authenticated RAG + external keys
//	GET /api/v1/retrieval/embedding — authenticated embedding config
//
// /api/v1/retrieval/reranking does NOT exist on Open WebUI (verified
// via full route enumeration in retrieval.py). Rerank config
// (RAG_EXTERNAL_RERANKER_API_KEY at retrieval.py:650-652) lives inside
// /api/v1/retrieval/config and is captured by the walker.
package openwebuiloot

import (
	"context"
	"encoding/json"
	"fmt"
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
	// walkerMaxDepth bounds the recursive secret walker over admin
	// config responses. Open WebUI's actual nesting is one level; 8
	// leaves ample margin against any future config restructuring.
	walkerMaxDepth = 8
	// walkerMinSecretLen skips likely-noise short strings. Real API
	// keys, tokens, subscription keys, and passwords are always
	// significantly longer than 7 chars.
	walkerMinSecretLen = 8
)

// Looter is the registered module.
type Looter struct{}

// RegisterFlags satisfies module.FlagsModule.
func (l *Looter) RegisterFlags(fs *pflag.FlagSet) {
	fs.String("api-key", "",
		"Open WebUI admin API key (or session JWT) for authenticated upstream-credential enumeration.")
}

// Loot probes Open WebUI. Anonymous mode always runs (posture props on
// the OpenWebUIInstance node). Authenticated mode runs only when an API
// key is supplied, emitting Credential nodes for configured upstream
// provider keys.
//
// opts.Extras key consumed by this Looter:
//
//	"api-key"  string — admin API key / JWT for authenticated probes
//
// The key is also read from opts.Credentials["api_key"] as a fallback
// so the generic --credential api_key=... path works too.
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

	client := common.NoRedirectClient(timeout)

	res := &action.LootResult{IngestData: &ingest.IngestData{}}

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
		props["probe_status"] = string(common.VerificationVerified)
		props["last_verified_at"] = time.Now().UTC().Format(time.RFC3339)
		if !cfg.AuthEnabled {
			props["auth_method"] = string(common.AuthNone)
			props["auth_assurance"] = string(common.AuthAssuranceUnauthenticated)
			props["auth_evidence"] = common.AuthEvidenceAnonymousProbeSucceeded
		} else if apiKey != "" {
			props["auth_method"] = string(common.AuthCustom)
			props["auth_assurance"] = string(common.AuthAssuranceUnknown)
			props["auth_evidence"] = common.AuthEvidenceConfiguredCredential
		} else {
			props["auth_method"] = string(common.AuthUnknown)
			props["auth_assurance"] = string(common.AuthAssuranceUnknown)
			props["auth_evidence"] = common.AuthEvidenceUnknown
		}
	}

	if apiKey == "" {
		slog.Info("openwebui loot complete",
			"endpoint", baseURL,
			"engagement_id", opts.EngagementID,
			"authenticated", false,
			"credentials_found", res.Summary.CredentialsFound,
			"partial_failures", res.Summary.PartialFailures)
		return res, nil
	}

	// 2. AUTHENTICATED probes — four admin-gated endpoints. Each is
	//    independent; a failure records a partial and the next probe
	//    still runs.
	remaining := maxItems
	remaining = runOpenAIConfig(ctx, client, res, opts, openwebuiID, baseURL, apiKey, remaining)
	remaining = runOllamaConfig(ctx, client, res, opts, openwebuiID, baseURL, apiKey, remaining)
	remaining = runRetrievalWalk(ctx, client, res, opts, openwebuiID, baseURL, apiKey,
		"/api/v1/retrieval/config", "retrieval_config", remaining)
	_ = runRetrievalWalk(ctx, client, res, opts, openwebuiID, baseURL, apiKey,
		"/api/v1/retrieval/embedding", "retrieval_embedding", remaining)

	slog.Info("openwebui loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"authenticated", true,
		"credentials_found", res.Summary.CredentialsFound,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// configPosture is the slice of GET /api/config the Looter promotes
// onto the OpenWebUIInstance node.
type configPosture struct {
	SignupEnabled bool
	AuthEnabled   bool
}

// fetchConfig issues GET /api/config (unauthenticated). Only reads the
// signup / auth flags — verified stable across all 14 sampled Open
// WebUI tags plus main. $.ollama.base_url was NEVER present on any
// version and was removed from this decoder in v0.4.
func fetchConfig(ctx context.Context, client *http.Client, baseURL string) (configPosture, error) {
	body, err := common.GetJSON(ctx, client, strings.TrimRight(baseURL, "/")+"/api/config", "", 4<<20)
	if err != nil {
		return configPosture{}, err
	}
	var raw struct {
		Features struct {
			Auth         *bool `json:"auth"`
			EnableSignup *bool `json:"enable_signup"`
		} `json:"features"`
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
	return c, nil
}

// probeGET issues a bearer-authenticated GET and records partial-failure
// bookkeeping. Returns the raw body when successful, nil otherwise.
func probeGET(
	ctx context.Context,
	client *http.Client,
	res *action.LootResult,
	opts action.LootOptions,
	baseURL, path, apiKey string,
) []byte {
	res.Summary.EndpointsProbed++
	body, err := common.GetJSON(ctx, client, strings.TrimRight(baseURL, "/")+path, apiKey, 4<<20)
	if err != nil {
		slog.Warn("openwebui loot: probe failed",
			"endpoint", baseURL+path,
			"key_prefix", common.Redact(apiKey),
			"engagement_id", opts.EngagementID,
			"error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("%s: %v", strings.TrimPrefix(path, "/"), err))
		res.Summary.PartialFailures++
		return nil
	}
	return body
}

// emitUpstreamCredential builds a :Credential node + EXPOSES_CREDENTIAL
// edge from a harvested upstream key and appends both to the LootResult.
func emitUpstreamCredential(
	res *action.LootResult,
	opts action.LootOptions,
	openwebuiID, baseURL string,
	nameSlug, format, value, endpoint, source string,
) {
	credID := ingest.ComputeNodeID("Credential", baseURL, nameSlug)
	cprops := map[string]any{
		"objectid":     credID,
		"type":         "apiKey",
		"name":         nameSlug,
		"source":       "openwebui",
		"high_entropy": true,
		"format":       format,
		"value_hash":   common.HashCredentialValue(value),
		"merge_key":    "value_hash",
	}
	common.ApplyCredentialEvidence(
		cprops,
		common.CredentialIdentityValueHash,
		common.CredentialMaterialObserved,
		common.CredentialExposureExposed,
	)
	if endpoint != "" {
		cprops["provider_endpoint"] = endpoint
	}
	if opts.IncludeCredentialValues {
		cprops["value"] = value
	}
	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:         credID,
		Kinds:      []string{"Credential"},
		Properties: cprops,
	})
	edgeEndpoint := endpoint
	if edgeEndpoint == "" {
		edgeEndpoint = baseURL
	}
	res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
		ingest.ExposesCredentialEdge(openwebuiID, credID, opts.EngagementID, source, edgeEndpoint))
	res.Summary.CredentialsFound++
}

// runOpenAIConfig probes GET /openai/config and emits one :Credential
// per non-empty OPENAI_API_KEYS[i], paired with OPENAI_API_BASE_URLS[i]
// when the arrays are parallel.
func runOpenAIConfig(
	ctx context.Context,
	client *http.Client,
	res *action.LootResult,
	opts action.LootOptions,
	openwebuiID, baseURL, apiKey string,
	remaining int,
) int {
	if remaining <= 0 {
		return 0
	}
	body := probeGET(ctx, client, res, opts, baseURL, "/openai/config", apiKey)
	if body == nil {
		return remaining
	}
	var raw struct {
		APIKeys     []string `json:"OPENAI_API_KEYS"`
		APIBaseURLs []string `json:"OPENAI_API_BASE_URLS"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("openai/config decode: %v", err))
		res.Summary.PartialFailures++
		return remaining
	}
	for i, key := range raw.APIKeys {
		if remaining <= 0 {
			break
		}
		key = strings.TrimSpace(key)
		if key == "" || len(key) < walkerMinSecretLen {
			continue
		}
		endpoint := ""
		if i < len(raw.APIBaseURLs) {
			endpoint = strings.TrimSpace(raw.APIBaseURLs[i])
		}
		emitUpstreamCredential(res, opts, openwebuiID, baseURL,
			"upstream-openai-"+strconv.Itoa(i), "upstream-provider", key, endpoint, "openai_config")
		remaining--
	}
	return remaining
}

// runOllamaConfig probes GET /ollama/config. For each entry in
// OLLAMA_BASE_URLS:
//
//   - Emits a placeholder :OllamaInstance node + :EXPOSES edge from
//     OpenWebUIInstance → OllamaInstance (matches what the old
//     fingerprinter tried to emit via the dead $.ollama.base_url capture).
//   - Looks up per-URL API key via OLLAMA_API_CONFIGS (keyed by index
//     "0"/"1"/… OR by the full base URL, per Open WebUI's get_api_key
//     double-fallback at routers/ollama.py:189-192). Decodes primary
//     field `key`; falls back to legacy `api_key`.
//   - Emits a :Credential + :EXPOSES_CREDENTIAL edge per non-empty key.
func runOllamaConfig(
	ctx context.Context,
	client *http.Client,
	res *action.LootResult,
	opts action.LootOptions,
	openwebuiID, baseURL, apiKey string,
	remaining int,
) int {
	if remaining <= 0 {
		return 0
	}
	body := probeGET(ctx, client, res, opts, baseURL, "/ollama/config", apiKey)
	if body == nil {
		return remaining
	}
	var raw struct {
		BaseURLs   []string                   `json:"OLLAMA_BASE_URLS"`
		APIConfigs map[string]json.RawMessage `json:"OLLAMA_API_CONFIGS"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("ollama/config decode: %v", err))
		res.Summary.PartialFailures++
		return remaining
	}

	// Track canonical URLs to promote onto the instance node.
	canonicalBaseURLs := make([]string, 0, len(raw.BaseURLs))

	for i, base := range raw.BaseURLs {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}
		canon := canonicalizeBackendURL(base)
		if canon == "" {
			continue
		}
		canonicalBaseURLs = append(canonicalBaseURLs, canon)

		// Emit placeholder :OllamaInstance node + :EXPOSES edge — one
		// per canonical backend URL. Uses ComputeNodeID with the
		// canonical URL so ollamafp / ollamaloot fold into the same
		// node via MERGE-by-objectid.
		ollamaID := ingest.ComputeNodeID("OllamaInstance", canon)
		placeholderIndex := len(res.IngestData.Graph.Nodes)
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID:    ollamaID,
			Kinds: []string{"OllamaInstance", "AIService"},
			Properties: map[string]any{
				"objectid":               ollamaID,
				"endpoint":               canon,
				"discovered_via":         "openwebui_ollama_config",
				"service_kind":           "ollama",
				"configuration_observed": true,
				"configured_via":         "openwebui",
				"configured_auth_method": string(common.AuthUnknown),
				"probe_status":           string(common.VerificationConfiguredUnverified),
			},
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, ingest.Edge{
			Source:     openwebuiID,
			Target:     ollamaID,
			Kind:       "EXPOSES",
			SourceKind: "OpenWebUIInstance",
			TargetKind: "OllamaInstance",
			Properties: map[string]any{
				"confidence":       1.0,
				"risk_weight":      0.3,
				"assertion_type":   "configured_reference",
				"confidence_scope": "configuration_presence",
				"evidence": map[string]any{
					"endpoint":      baseURL,
					"source":        "ollama_config",
					"engagement_id": opts.EngagementID,
					"backend_url":   canon,
				},
			},
		})

		if remaining <= 0 {
			continue
		}
		// Per-URL config lookup: index-keyed → base-URL-keyed →
		// canonical-URL-keyed. Decodes `key` primarily, `api_key` as
		// legacy fallback.
		var cfgRaw json.RawMessage
		if v, ok := raw.APIConfigs[strconv.Itoa(i)]; ok {
			cfgRaw = v
		} else if v, ok := raw.APIConfigs[base]; ok {
			cfgRaw = v
		} else if v, ok := raw.APIConfigs[canon]; ok {
			cfgRaw = v
		}
		if len(cfgRaw) == 0 {
			continue
		}
		var cfg struct {
			Key    string `json:"key"`
			APIKey string `json:"api_key"`
		}
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			continue
		}
		key := strings.TrimSpace(cfg.Key)
		if key == "" {
			key = strings.TrimSpace(cfg.APIKey)
		}
		if key == "" || len(key) < walkerMinSecretLen {
			continue
		}
		res.IngestData.Graph.Nodes[placeholderIndex].Properties["configured_auth_method"] =
			string(common.AuthAPIKey)
		emitUpstreamCredential(res, opts, openwebuiID, baseURL,
			"upstream-ollama-"+strconv.Itoa(i), "upstream-ollama", key, canon, "ollama_config")
		remaining--
	}

	// Promote the canonicalized base URLs onto the OpenWebUIInstance posture.
	if len(canonicalBaseURLs) > 0 {
		props := res.IngestData.Graph.Nodes[0].Properties
		props["ollama_backend_urls"] = canonicalBaseURLs
	}
	return remaining
}

// runRetrievalWalk probes an admin-gated retrieval endpoint and runs
// the recursive secret walker over the response, emitting one
// :Credential per matched secret field.
func runRetrievalWalk(
	ctx context.Context,
	client *http.Client,
	res *action.LootResult,
	opts action.LootOptions,
	openwebuiID, baseURL, apiKey, path, source string,
	remaining int,
) int {
	if remaining <= 0 {
		return 0
	}
	body := probeGET(ctx, client, res, opts, baseURL, path, apiKey)
	if body == nil {
		return remaining
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		res.PartialErrors = append(res.PartialErrors,
			fmt.Sprintf("%s decode: %v", strings.TrimPrefix(path, "/"), err))
		res.Summary.PartialFailures++
		return remaining
	}
	harvested := walkSecretFields(root, nil, remaining, walkerMaxDepth)
	for _, hc := range harvested {
		if remaining <= 0 {
			break
		}
		emitUpstreamCredential(res, opts, openwebuiID, baseURL,
			"openwebui-"+source+"-"+hc.PathSlug,
			"openwebui-"+source,
			hc.Value,
			"",
			source)
		remaining--
	}
	return remaining
}

// harvested is one match from the recursive secret walker.
type harvested struct {
	PathSlug string
	Value    string
}

// isSecretKey reports whether a JSON key name looks like it holds a
// secret. Match is case-insensitive so both flat UPPER_SNAKE
// (RAG_EXTERNAL_RERANKER_API_KEY, PADDLEOCR_VL_TOKEN, YACY_PASSWORD,
// BING_SEARCH_V7_SUBSCRIPTION_KEY, SOUGOU_API_SK) and nested lowercase
// (openai_config.key) shapes hit.
//
// Negative filters skip common non-secret fields that would otherwise
// match a positive suffix (RAG_TOKENIZER_MODEL contains "TOKEN" but is
// an engine identifier; SEARCHAPI_ENGINE / SEARXNG_LANGUAGE contain no
// positive suffix but are guarded belt-and-braces).
func isSecretKey(key string) bool {
	upper := strings.ToUpper(key)
	// Negative filter first — a positive suffix that co-occurs with any
	// of these tokens is presumed non-secret.
	negatives := []string{
		"MODEL", "ENGINE", "URL", "HOST", "NAME", "MODE",
		"TYPE", "PATH", "DIR", "FORMAT", "LANGUAGE", "TEMPLATE",
		"TIMEOUT", "PARAMS", "SIZE", "COUNT",
	}
	for _, n := range negatives {
		if strings.Contains(upper, n) {
			return false
		}
	}
	positives := []string{"KEY", "TOKEN", "PASSWORD", "SECRET", "SUBSCRIPTION"}
	for _, p := range positives {
		if strings.Contains(upper, p) {
			return true
		}
	}
	// _SK trailing suffix — Sougou-style shorthand.
	if strings.HasSuffix(upper, "_SK") {
		return true
	}
	return false
}

// walkSecretFields recurses into every nested object in root, emitting
// one entry per terminal string value whose key name matches
// isSecretKey and whose value clears walkerMinSecretLen. Path is a
// breadcrumb slice used to build the credential's name slug (dotted
// path, snake_cased).
func walkSecretFields(root map[string]json.RawMessage, path []string, maxItems, depth int) []harvested {
	if depth <= 0 || maxItems <= 0 {
		return nil
	}
	var out []harvested
	for k, raw := range root {
		if len(out) >= maxItems {
			break
		}
		bread := append(append([]string(nil), path...), k)
		// Try string first.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			if !isSecretKey(k) {
				continue
			}
			v := strings.TrimSpace(s)
			if len(v) < walkerMinSecretLen {
				continue
			}
			out = append(out, harvested{
				PathSlug: pathToSlug(bread),
				Value:    v,
			})
			continue
		}
		// Try nested object.
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err == nil && nested != nil {
			for _, hc := range walkSecretFields(nested, bread, maxItems-len(out), depth-1) {
				if len(out) >= maxItems {
					break
				}
				out = append(out, hc)
			}
		}
		// Arrays and other scalar types (bool, number, null) are
		// intentionally ignored — Open WebUI admin secrets are always
		// strings.
	}
	return out
}

// pathToSlug renders a breadcrumb path as a lowercase dotted
// identifier suitable for use in a Credential node's name property.
func pathToSlug(path []string) string {
	cleaned := make([]string, 0, len(path))
	for _, p := range path {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		cleaned = append(cleaned, p)
	}
	return strings.Join(cleaned, ".")
}

var _ action.Looter = (*Looter)(nil)
var _ interface {
	RegisterFlags(*pflag.FlagSet)
} = (*Looter)(nil)

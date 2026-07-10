// Package jupyterloot implements the v0.4 Jupyter Looter.
//
// Jupyter Server (default port 8888) exposes an anonymous REST API on
// default deployments: /api/sessions (running kernels) and
// /api/contents/ (notebook directory listing). Notebook cell content
// itself is available via /api/contents/<path>?content=1, also
// anonymous when the token gate is unset (common in containerized lab
// deployments).
//
// The anonymous surface is the primary loot path:
//
//	GET /api/sessions          — list active sessions (kernel IDs)
//	GET /api/contents/<path>   — per-directory listing (recursive walk)
//
// The contents walk is genuinely recursive: the Looter iterates the
// root directory listing and descends into every child of type
// "directory", bounded by --max-depth (default 4). Any per-directory
// non-2xx (403, 404, 500) is recorded as a partial failure and the
// walk continues on sibling directories — one hostile or auth-locked
// subtree cannot mask notebooks elsewhere in the tree.
//
// This Looter emits:
//   - One :JupyterServer node (MERGE-safe with fingerprinter)
//   - One :MCPResource per notebook or file discovered in the tree
//     (uri scheme "jupyter://<host>:<port>/<path>")
//
// v0.4 scope: sessions + recursive directory listing. Notebook-content
// extraction (cell-level loot) stays out until the Extractor interface
// proves itself on the embedding-inversion PoC.
package jupyterloot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	DefaultPort         = 8888
	DefaultProbeTimeout = 30 * time.Second
	DefaultMaxItems     = 500
	// DefaultMaxDepth bounds the recursive /api/contents walk.
	// Arbitrary safety cap: Jupyter Server places no upper bound on
	// directory nesting depth, so a hostile or accidentally deep tree
	// could exhaust the Looter without this bound. 4 is a middle
	// ground: real-world notebook trees rarely exceed 3 levels.
	DefaultMaxDepth = 4
)

type Looter struct{}

// RegisterFlags satisfies module.FlagsModule.
func (l *Looter) RegisterFlags(fs *pflag.FlagSet) {
	fs.Int("max-depth", DefaultMaxDepth,
		"Maximum recursion depth into /api/contents subdirectories. Arbitrary safety cap — Jupyter Server places no upper bound on tree depth, so a hostile or accidentally-deep tree could exhaust the Looter without one.")
}

func (l *Looter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	_, host, port := action.EndpointParts(t, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(t, DefaultPort, "http")
	jupyterID := ingest.ComputeNodeID("JupyterServer", baseURL)

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}
	maxDepth, _ := opts.Extras["max-depth"].(int)
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}

	client := common.NoRedirectClient(timeout)

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
		// Empty-path sessions (fresh console kernels) are real running
		// kernels; count them.
		res.IngestData.Graph.Nodes[0].Properties["active_sessions"] = len(sessions)
	}

	// Probe /api/contents/ recursively.
	notebooks, perDirErrs, err := fetchContentsRecursive(ctx, client, baseURL, "", maxItems, maxDepth)
	res.Summary.EndpointsProbed++
	if err != nil {
		slog.Warn("jupyter loot: /api/contents failed", "error", err)
		res.PartialErrors = append(res.PartialErrors, fmt.Sprintf("api/contents: %v", err))
		res.Summary.PartialFailures++
	}
	for _, pe := range perDirErrs {
		slog.Debug("jupyter loot: subdirectory listing failed", "error", pe)
		res.PartialErrors = append(res.PartialErrors, pe)
		res.Summary.PartialFailures++
	}
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
		res.IngestData.Graph.Edges = append(res.IngestData.Graph.Edges,
			ingest.Edge{
				Source:     jupyterID,
				Target:     resID,
				Kind:       "PROVIDES_RESOURCE",
				SourceKind: "JupyterServer",
				TargetKind: "MCPResource",
				Properties: map[string]any{
					"confidence":  1.0,
					"risk_weight": 0.2,
					"evidence": map[string]any{
						"endpoint":      baseURL,
						"source":        "api/contents",
						"engagement_id": opts.EngagementID,
					},
				},
			})
	}

	slog.Info("jupyter loot complete",
		"endpoint", baseURL,
		"engagement_id", opts.EngagementID,
		"notebooks_found", len(notebooks),
		"per_directory_failures", len(perDirErrs),
		"partial_failures", res.Summary.PartialFailures)
	return res, nil
}

// session is the shape the Looter reads from /api/sessions. Only Path
// and Name are actually consumed. (Upstream jupyter_server still emits
// a deprecated `notebook: {path, name}` sub-object for
// `type=="notebook"` sessions, but this Looter has no downstream use
// for it — the notebook path is already surfaced via /api/contents.)
type session struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Name string `json:"name"`
}

func fetchSessions(ctx context.Context, client *http.Client, baseURL string) ([]session, error) {
	body, err := common.GetJSON(ctx, client, baseURL+"/api/sessions", "", 4<<20)
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

// dirNode holds one queued directory walk.
type dirNode struct {
	path  string
	depth int
}

// fetchContentsRecursive walks Jupyter's /api/contents tree
// breadth-first, seeded at rootPath and bounded by maxItems + maxDepth.
// Returns (leaf-entries, per-directory-errors, fatal-error). A non-2xx
// on the root call is fatal (fingerprint concern — no notebooks
// discoverable). A non-2xx on any subdirectory is recorded in the
// per-directory-errors slice and the walk continues on siblings. Leaf
// filter matches type=="notebook" or type=="file".
func fetchContentsRecursive(ctx context.Context, client *http.Client, baseURL, rootPath string, maxItems, maxDepth int) ([]contentsEntry, []string, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}

	rootEntries, err := fetchDirectory(ctx, client, baseURL, rootPath)
	if err != nil {
		return nil, nil, err
	}

	var out []contentsEntry
	var perDirErrs []string
	queue := []dirNode{}

	appendEntries := func(entries []contentsEntry, currentDepth int) {
		for _, e := range entries {
			if len(out) >= maxItems {
				return
			}
			switch e.Type {
			case "notebook", "file":
				out = append(out, e)
			case "directory":
				// Only enqueue if depth budget permits.
				if currentDepth+1 <= maxDepth {
					queue = append(queue, dirNode{path: e.Path, depth: currentDepth + 1})
				}
			}
		}
	}

	// Root is depth 1 for the purpose of the depth cap: subdirectories
	// under root are depth 2, etc. This matches the operator-intuitive
	// "how many levels deep" interpretation.
	appendEntries(rootEntries, 1)

	for len(queue) > 0 && len(out) < maxItems {
		next := queue[0]
		queue = queue[1:]
		entries, err := fetchDirectory(ctx, client, baseURL, next.path)
		if err != nil {
			perDirErrs = append(perDirErrs,
				fmt.Sprintf("api/contents/%s: %v", next.path, err))
			continue
		}
		appendEntries(entries, next.depth)
	}
	return out, perDirErrs, nil
}

// fetchDirectory issues one GET /api/contents/<path> and returns the
// directory's Content slice. Non-2xx is surfaced verbatim from
// common.GetJSON.
func fetchDirectory(ctx context.Context, client *http.Client, baseURL, path string) ([]contentsEntry, error) {
	u := baseURL + "/api/contents/" + path
	body, err := common.GetJSON(ctx, client, u, "", 4<<20)
	if err != nil {
		return nil, err
	}
	var dir struct {
		Content []contentsEntry `json:"content"`
	}
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, fmt.Errorf("decode contents: %w", err)
	}
	return dir.Content, nil
}

var _ action.Looter = (*Looter)(nil)
var _ interface {
	RegisterFlags(*pflag.FlagSet)
} = (*Looter)(nil)

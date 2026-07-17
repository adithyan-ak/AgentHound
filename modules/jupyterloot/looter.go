// Package jupyterloot inventories Jupyter sessions and contents through
// protected operations. Every protected root is attempted without credentials
// first; only a 401/403 triggers a retry with opts.Credentials["token"].
package jupyterloot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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
	maxJSONBody         = 4 << 20
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

func (l *Looter) Loot(
	ctx context.Context,
	target action.Target,
	opts action.LootOptions,
) (*action.LootResult, error) {
	_, host, port := action.EndpointParts(target, DefaultPort, "http")
	baseURL := action.EndpointBaseURL(target, DefaultPort, "http")
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
	token, err := normalizeSuppliedToken(opts.Credentials["token"])
	if err != nil {
		return nil, errors.New("jupyter loot: invalid token credential")
	}

	client := common.NoRedirectClient(timeout)
	res := &action.LootResult{IngestData: &ingest.IngestData{}}

	sessions, sessionsAccess, sessionsErr := fetchSessionsWithFallback(
		ctx,
		client,
		baseURL,
		token,
	)
	res.Summary.EndpointsProbed++
	if sessionsErr != nil {
		slog.Warn("jupyter loot: /api/sessions failed", "error", sessionsErr)
		res.PartialErrors = append(
			res.PartialErrors,
			fmt.Sprintf("api/sessions: %v", sessionsErr),
		)
		res.Summary.PartialFailures++
	}

	notebooks, perDirErrs, contentsAccess, contentsTruncation, contentsErr := fetchContentsRecursive(
		ctx,
		client,
		baseURL,
		"",
		maxItems,
		maxDepth,
		token,
	)
	res.Summary.EndpointsProbed++
	if contentsErr != nil {
		slog.Warn("jupyter loot: /api/contents failed", "error", contentsErr)
		res.PartialErrors = append(
			res.PartialErrors,
			fmt.Sprintf("api/contents: %v", contentsErr),
		)
		res.Summary.PartialFailures++
	}
	if contentsTruncation.maxItems {
		res.PartialErrors = append(
			res.PartialErrors,
			fmt.Sprintf("api/contents: truncated at --max-items=%d", maxItems),
		)
		res.Summary.PartialFailures++
	}
	if contentsTruncation.maxDepth {
		res.PartialErrors = append(
			res.PartialErrors,
			fmt.Sprintf("api/contents: truncated at --max-depth=%d", maxDepth),
		)
		res.Summary.PartialFailures++
	}
	for _, perDirectoryErr := range perDirErrs {
		slog.Debug(
			"jupyter loot: subdirectory listing failed",
			"error",
			perDirectoryErr,
		)
		res.PartialErrors = append(res.PartialErrors, perDirectoryErr)
		res.Summary.PartialFailures++
	}

	props := map[string]any{
		"objectid":      jupyterID,
		"endpoint":      baseURL,
		"name":          host,
		"loot_observed": true,
		"service_kind":  "jupyter",
	}
	if sessionsErr == nil {
		props["active_sessions"] = len(sessions)
	}
	applyProtectedAccessProperties(props, sessionsAccess, contentsAccess)
	res.IngestData.Graph.Nodes = append(
		res.IngestData.Graph.Nodes,
		ingest.Node{
			ID:         jupyterID,
			Kinds:      []string{"JupyterServer", "AIService"},
			Properties: props,
		},
	)

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

type accessEvidence struct {
	anonymousSucceeded bool
	bearerSucceeded    bool
	denied             bool
}

func (a *accessEvidence) merge(other accessEvidence) {
	a.anonymousSucceeded = a.anonymousSucceeded || other.anonymousSucceeded
	a.bearerSucceeded = a.bearerSucceeded || other.bearerSucceeded
	a.denied = a.denied || other.denied
}

func (a accessEvidence) label() string {
	evidenceKinds := 0
	if a.anonymousSucceeded {
		evidenceKinds++
	}
	if a.bearerSucceeded {
		evidenceKinds++
	}
	if a.denied {
		evidenceKinds++
	}
	if evidenceKinds > 1 {
		return "mixed"
	}
	switch {
	case a.anonymousSucceeded:
		return "anonymous"
	case a.bearerSucceeded:
		return "bearer"
	case a.denied:
		return "denied"
	default:
		return "unknown"
	}
}

func (a accessEvidence) requiresAuthentication() bool {
	return a.bearerSucceeded || a.denied
}

func (a accessEvidence) onlyAnonymous() bool {
	return a.anonymousSucceeded && !a.bearerSucceeded && !a.denied
}

func (a accessEvidence) onlyBearer() bool {
	return a.bearerSucceeded && !a.anonymousSucceeded && !a.denied
}

func applyProtectedAccessProperties(
	props map[string]any,
	sessions accessEvidence,
	contents accessEvidence,
) {
	props["sessions_access"] = sessions.label()
	props["contents_access"] = contents.label()

	anonymousObserved :=
		sessions.anonymousSucceeded || contents.anonymousSucceeded
	props["anonymous_access_observed"] = anonymousObserved
	props["is_anonymous_loot"] = anonymousObserved

	method := common.AuthUnknown
	evidence := common.AuthEvidenceUnknown
	switch {
	case sessions.onlyAnonymous() && contents.onlyAnonymous():
		props["auth_required"] = false
		method = common.AuthNone
		evidence = common.AuthEvidenceAnonymousProbeSucceeded
	case sessions.onlyBearer() && contents.onlyBearer():
		props["auth_required"] = true
		method = common.AuthBearer
		evidence = common.AuthEvidenceConfiguredCredential
	default:
		if sessions.requiresAuthentication() ||
			contents.requiresAuthentication() {
			props["auth_required"] = true
		}
	}
	assessment := common.AssessAuth(string(method))
	props["auth_method"] = string(method)
	props["auth_assurance"] = string(assessment.Assurance)
	props["auth_evidence"] = evidence
}

type session struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Name string `json:"name"`
}

func fetchSessionsWithFallback(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	token string,
) ([]session, accessEvidence, error) {
	sessions, err := fetchSessions(ctx, client, baseURL, "")
	if err == nil {
		return sessions, accessEvidence{anonymousSucceeded: true}, nil
	}
	if !isAuthenticationDenial(err) {
		return nil, accessEvidence{}, err
	}
	if token == "" {
		return nil, accessEvidence{denied: true}, err
	}
	sessions, err = fetchSessions(ctx, client, baseURL, token)
	if err != nil {
		return nil, accessEvidence{denied: true}, err
	}
	return sessions, accessEvidence{bearerSucceeded: true}, nil
}

func fetchSessions(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	token string,
) ([]session, error) {
	body, err := getJSON(
		ctx,
		client,
		baseURL+"/api/sessions",
		token,
		maxJSONBody,
	)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		return nil, errors.New("decode sessions: expected a JSON array")
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
	Type     string `json:"type"`
	MimeType string `json:"mimetype"`
}

type dirNode struct {
	path   string
	depth  int
	bearer string
}

type contentsTruncation struct {
	maxItems bool
	maxDepth bool
}

func fetchContentsRecursive(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	rootPath string,
	maxItems int,
	maxDepth int,
	token string,
) ([]contentsEntry, []string, accessEvidence, contentsTruncation, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}

	rootEntries, rootBearer, access, err := fetchDirectoryWithFallback(
		ctx,
		client,
		baseURL,
		rootPath,
		"",
		token,
	)
	if err != nil {
		return nil, nil, access, contentsTruncation{}, err
	}

	var out []contentsEntry
	var perDirErrs []string
	queue := []dirNode{}
	itemsSeen := 0
	truncation := contentsTruncation{}

	appendEntries := func(
		entries []contentsEntry,
		currentDepth int,
		bearer string,
	) {
		for _, e := range entries {
			if itemsSeen >= maxItems {
				truncation.maxItems = true
				return
			}
			itemsSeen++
			switch e.Type {
			case "notebook", "file":
				out = append(out, e)
			case "directory":
				if currentDepth+1 <= maxDepth {
					queue = append(queue, dirNode{
						path:   e.Path,
						depth:  currentDepth + 1,
						bearer: bearer,
					})
				} else {
					truncation.maxDepth = true
				}
			}
		}
	}
	appendEntries(rootEntries, 1, rootBearer)

	for len(queue) > 0 && !truncation.maxItems {
		next := queue[0]
		queue = queue[1:]
		entries, bearer, directoryAccess, fetchErr :=
			fetchDirectoryWithFallback(
				ctx,
				client,
				baseURL,
				next.path,
				next.bearer,
				token,
			)
		access.merge(directoryAccess)
		if fetchErr != nil {
			perDirErrs = append(
				perDirErrs,
				fmt.Sprintf("api/contents/%s: %v", next.path, fetchErr),
			)
			continue
		}
		appendEntries(entries, next.depth, bearer)
	}
	return out, perDirErrs, access, truncation, nil
}

func fetchDirectoryWithFallback(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	path string,
	preferredBearer string,
	suppliedToken string,
) ([]contentsEntry, string, accessEvidence, error) {
	if preferredBearer != "" {
		entries, err := fetchDirectory(
			ctx,
			client,
			baseURL,
			path,
			preferredBearer,
		)
		if err != nil {
			if isAuthenticationDenial(err) {
				return nil, preferredBearer, accessEvidence{denied: true}, err
			}
			return nil, preferredBearer, accessEvidence{}, err
		}
		return entries, preferredBearer, accessEvidence{bearerSucceeded: true}, nil
	}

	entries, err := fetchDirectory(ctx, client, baseURL, path, "")
	if err == nil {
		return entries, "", accessEvidence{anonymousSucceeded: true}, nil
	}
	if !isAuthenticationDenial(err) {
		return nil, "", accessEvidence{}, err
	}
	if suppliedToken == "" {
		return nil, "", accessEvidence{denied: true}, err
	}
	entries, err = fetchDirectory(
		ctx,
		client,
		baseURL,
		path,
		suppliedToken,
	)
	if err != nil {
		return nil, suppliedToken, accessEvidence{denied: true}, err
	}
	return entries, suppliedToken, accessEvidence{bearerSucceeded: true}, nil
}

func fetchDirectory(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	path string,
	token string,
) ([]contentsEntry, error) {
	endpoint := baseURL + "/api/contents/"
	if path != "" {
		segments := strings.Split(path, "/")
		for i := range segments {
			segments[i] = url.PathEscape(segments[i])
		}
		endpoint += strings.Join(segments, "/")
	}
	body, err := getJSON(ctx, client, endpoint, token, maxJSONBody)
	if err != nil {
		return nil, err
	}
	var dir struct {
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, fmt.Errorf("decode contents: %w", err)
	}
	content := strings.TrimSpace(string(dir.Content))
	if !strings.HasPrefix(content, "[") {
		return nil, errors.New(
			"decode contents: expected a directory content array",
		)
	}
	var entries []contentsEntry
	if err := json.Unmarshal(dir.Content, &entries); err != nil {
		return nil, fmt.Errorf("decode contents array: %w", err)
	}
	return entries, nil
}

type statusError struct {
	code int
}

func (e statusError) Error() string {
	return fmt.Sprintf("status %d", e.code)
}

func isAuthenticationDenial(err error) bool {
	var status statusError
	return errors.As(err, &status) &&
		(status.code == http.StatusUnauthorized ||
			status.code == http.StatusForbidden)
}

func getJSON(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	bearer string,
	limit int64,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	if resp.StatusCode < http.StatusOK ||
		resp.StatusCode >= http.StatusMultipleChoices {
		return nil, statusError{code: resp.StatusCode}
	}
	return body, nil
}

func normalizeSuppliedToken(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "\r\n\t") {
		return "", errors.New("invalid whitespace")
	}
	parts := strings.Split(value, " ")
	switch {
	case len(parts) == 1 && !strings.EqualFold(parts[0], "Bearer"):
		return parts[0], nil
	case len(parts) == 2 &&
		strings.EqualFold(parts[0], "Bearer") &&
		parts[1] != "":
		return parts[1], nil
	default:
		return "", errors.New("must be a bare token or one Bearer-prefixed token")
	}
}

var _ action.Looter = (*Looter)(nil)
var _ interface {
	RegisterFlags(*pflag.FlagSet)
} = (*Looter)(nil)

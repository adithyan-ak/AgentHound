// Package mcppoison implements the v0.4 MCP-tool-description Poisoner.
//
// Threat model. A typical MCP server exposes tool metadata via the
// JSON-RPC `tools/list` method; the description field is consumed by
// agents at session-init and used by the LLM to decide which tool to
// invoke for a given user request. An attacker who can rewrite the
// description string can change agent behavior at the planning step
// without touching tool code — the canonical "tool description
// poisoning" path documented in the OWASP MCP Top 10 (MCP02) and the
// Anthropic MCP security report.
//
// Real-world poisoning paths vary by server implementation. There is
// no standard MCP "tools/update" RPC — servers either expose an admin
// HTTP endpoint, store tools in a config file the agent reloads, or
// register them via a database row. Operators specify the write path
// at poison time via --update-method + --update-path; this module
// dispatches whatever the operator says. The receipt captures the
// ORIGINAL description (read via tools/list) so revert restores it
// regardless of which write path was used to inject.
//
// Safety gates (per the v0.3-v0.4 implementation plan):
//
//  1. Reverter is COMPILE-TIME mandatory — Poisoner embeds Reverter,
//     so this module won't compile without Revert.
//  2. --commit=false is the CLI default; without it, the module runs
//     end-to-end (reads original, computes injection, persists receipt
//     with DryRun=true) but skips the mutating HTTP write.
//  3. AUTHORIZED prompt + ~/.agenthound/poison-acknowledged sentinel
//     gate first-time invocation. Wired in collector/cli/poison.go.
//  4. Receipt persistence via StatefulModule before "applied" success
//     report — a crash between the HTTP write and the receipt write
//     would otherwise leave a tampered target without a revert path.
package mcppoison

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

const (
	DefaultProbeTimeout = 30 * time.Second

	// DefaultUpdateMethod is the HTTP method we issue when the operator
	// doesn't override. PUT is conventional for tool admin endpoints
	// where the body is the entire new tool descriptor.
	DefaultUpdateMethod = "PUT"

	// DefaultUpdatePathTemplate is the path template the demo MCP-stub
	// implements (see docker/demo/v0.3/mcp-stub/app.py). For real
	// engagements the operator overrides via --update-path so the
	// module can talk to whatever admin surface the target exposes.
	DefaultUpdatePathTemplate = "/admin/tools/{id}"

	// DefaultListPath is where we GET the JSON-RPC tools/list response
	// to read the current description. Most MCP servers respond at "/"
	// or "/mcp"; the operator can override with --list-path.
	DefaultListPath = "/"
)

// Poisoner is the registered module.
type Poisoner struct {
	stateful module.StatefulModule
}

// New constructs a Poisoner with a default file-backed StatefulModule.
// Tests can swap the StatefulModule after construction.
func New() *Poisoner {
	return &Poisoner{
		stateful: module.NewFileStatefulModule("mcp.poison"),
	}
}

// Stateful exposes the embedded StatefulModule so the CLI revert verb
// can read receipts without going through GetByTarget.
func (p *Poisoner) Stateful() module.StatefulModule { return p.stateful }

// SetStateful overrides the StatefulModule (test-only — production
// code paths do not need this).
func (p *Poisoner) SetStateful(s module.StatefulModule) { p.stateful = s }

// RegisterFlags satisfies module.FlagsModule.
func (p *Poisoner) RegisterFlags(fs *pflag.FlagSet) {
	fs.String("update-method", DefaultUpdateMethod,
		"HTTP method for the tool description update (default PUT).")
	fs.String("update-path", DefaultUpdatePathTemplate,
		"Path template for the update request; '{id}' is replaced with --target-id.")
	fs.String("list-path", DefaultListPath,
		"Path for the JSON-RPC tools/list call used to read the original description.")
	fs.String("auth-token", "",
		"Optional bearer token sent with both list and update requests.")
}

// Poison reads the current tool description, applies the injection per
// payload.Mode, persists a receipt, and (when DryRun=false) issues the
// mutating HTTP write. Returns the receipt regardless of DryRun so the
// CLI can present a uniform success story.
func (p *Poisoner) Poison(ctx context.Context, t action.Target, payload action.PoisonPayload) (*action.PoisonReceipt, error) {
	if payload.TargetID == "" {
		return nil, errors.New("mcp poison: --target-id is required")
	}
	if payload.InjectionContent == "" {
		return nil, errors.New("mcp poison: --inject is required")
	}

	updateMethod, _ := payload.Extras["update-method"].(string)
	if updateMethod == "" {
		updateMethod = DefaultUpdateMethod
	}
	updatePath, _ := payload.Extras["update-path"].(string)
	if updatePath == "" {
		updatePath = DefaultUpdatePathTemplate
	}
	listPath, _ := payload.Extras["list-path"].(string)
	if listPath == "" {
		listPath = DefaultListPath
	}
	authToken, _ := payload.Extras["auth-token"].(string)

	mode := payload.Mode
	if mode == "" {
		mode = "replace"
	}
	switch mode {
	case "replace", "append", "prepend":
	default:
		return nil, fmt.Errorf("mcp poison: unsupported --mode %q (use replace/append/prepend)", mode)
	}

	baseURL := strings.TrimRight(targetBaseURL(t), "/")
	client := &http.Client{Timeout: DefaultProbeTimeout}

	original, err := fetchToolDescription(ctx, client, baseURL, listPath, payload.TargetID, authToken)
	if err != nil {
		return nil, fmt.Errorf("read original tool description: %w", err)
	}

	injected := composeContent(original, payload.InjectionContent, mode)

	receipt := &action.PoisonReceipt{
		ModuleID:        "mcp.poison",
		EngagementID:    payload.EngagementID,
		Target:          t,
		TargetID:        payload.TargetID,
		OriginalContent: original,
		InjectedContent: injected,
		Mode:            mode,
		AppliedAt:       time.Now().UTC(),
		DryRun:          payload.DryRun,
		Extra: map[string]any{
			"update_method": updateMethod,
			"update_path":   updatePath,
			"list_path":     listPath,
			"base_url":      baseURL,
		},
	}

	if payload.DryRun {
		slog.Info("mcp poison dry-run",
			"target_id", payload.TargetID,
			"engagement_id", payload.EngagementID,
			"mode", mode)
		return receipt, nil
	}

	// Safety gate 4: persist the receipt BEFORE the mutating HTTP write.
	// A crash after the HTTP write but before receipt persistence would
	// leave the target tampered with no revert path. Persisting first
	// ensures the operator can always revert.
	if _, err := p.stateful.WriteReceipt(payload.EngagementID, receipt); err != nil {
		return nil, fmt.Errorf("persist receipt before mutation: %w", err)
	}

	if err := writeToolDescription(ctx, client, baseURL, updateMethod, updatePath, payload.TargetID, injected, authToken); err != nil {
		return nil, fmt.Errorf("apply poison: %w", err)
	}

	slog.Info("mcp poison applied",
		"target_id", payload.TargetID,
		"engagement_id", payload.EngagementID,
		"mode", mode,
		"original_bytes", len(original),
		"injected_bytes", len(injected))
	return receipt, nil
}

// Revert restores the original tool description recorded on the
// receipt. Idempotent: if the current description on the target
// already equals OriginalContent, Revert is a no-op (returns nil).
//
// receipt may be either *action.PoisonReceipt or action.PoisonReceipt
// (the StatefulModule encoder normalizes to pointer on read; defensive
// dereference in case a caller hands a value).
func (p *Poisoner) Revert(ctx context.Context, receipt action.Receipt) error {
	r, ok := normalizeReceipt(receipt)
	if !ok {
		return fmt.Errorf("mcp poison revert: unexpected receipt type %T", receipt)
	}
	if r.DryRun {
		// Dry-run receipts never mutated anything; revert is a no-op.
		return nil
	}
	updateMethod, _ := r.Extra["update_method"].(string)
	if updateMethod == "" {
		updateMethod = DefaultUpdateMethod
	}
	updatePath, _ := r.Extra["update_path"].(string)
	if updatePath == "" {
		updatePath = DefaultUpdatePathTemplate
	}
	listPath, _ := r.Extra["list_path"].(string)
	if listPath == "" {
		listPath = DefaultListPath
	}
	baseURL, _ := r.Extra["base_url"].(string)
	if baseURL == "" {
		baseURL = strings.TrimRight(targetBaseURL(r.Target), "/")
	}
	authToken, _ := ctx.Value(action.RevertAuthTokenKey{}).(string)

	client := &http.Client{Timeout: DefaultProbeTimeout}

	// Idempotency check — if the current description already equals
	// OriginalContent, we have nothing to do. The check protects against
	// double-revert and against an out-of-band restore that beat us to it.
	current, err := fetchToolDescription(ctx, client, baseURL, listPath, r.TargetID, authToken)
	if err == nil && current == r.OriginalContent {
		slog.Info("mcp poison revert: target already matches original (no-op)",
			"target_id", r.TargetID,
			"engagement_id", r.EngagementID)
		return nil
	}

	if err := writeToolDescription(ctx, client, baseURL, updateMethod, updatePath, r.TargetID, r.OriginalContent, authToken); err != nil {
		return fmt.Errorf("write original back: %w", err)
	}
	slog.Info("mcp poison reverted",
		"target_id", r.TargetID,
		"engagement_id", r.EngagementID)
	return nil
}

// composeContent returns the new description according to mode. The
// caller validated mode before this is reached.
func composeContent(original, injection, mode string) string {
	switch mode {
	case "append":
		return original + injection
	case "prepend":
		return injection + original
	default:
		return injection
	}
}

// targetBaseURL builds the http(s)://host[:port] URL the module talks to.
// Looks for an explicit "url" override in Target.Meta first, then falls
// back to Address with scheme inferred from Meta["scheme"] (default http).
func targetBaseURL(t action.Target) string {
	if u, ok := t.Meta["url"]; ok && u != "" {
		return u
	}
	scheme := "http"
	if s, ok := t.Meta["scheme"]; ok && s != "" {
		scheme = s
	}
	return scheme + "://" + t.Address
}

// fetchToolDescription issues a JSON-RPC tools/list request and pulls
// the description for the named tool. Returns "" with an error if the
// tool is not present in the response.
func fetchToolDescription(ctx context.Context, client *http.Client, baseURL, listPath, toolID, authToken string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})
	url := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(listPath, "/")
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("tools/list request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("tools/list status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var parsed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("decode tools/list: %w", err)
	}
	for _, tool := range parsed.Result.Tools {
		if tool.Name == toolID {
			return tool.Description, nil
		}
	}
	return "", fmt.Errorf("tool %q not found in tools/list response", toolID)
}

// writeToolDescription issues the operator-specified mutating request.
// Body shape is {"description": "..."} — the demo stub accepts this
// shape; real targets may need a richer body, in which case the
// operator should write a custom Poisoner module rather than extend
// this one (the v0.3-v0.4 plan locks one Poisoner per surface).
func writeToolDescription(ctx context.Context, client *http.Client, baseURL, method, pathTpl, toolID, newDesc, authToken string) error {
	path := strings.ReplaceAll(pathTpl, "{id}", toolID)
	url := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
	body, _ := json.Marshal(map[string]any{"description": newDesc})
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("update request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drained, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("update status %d: %s", resp.StatusCode, strings.TrimSpace(string(drained)))
	}
	return nil
}

func normalizeReceipt(r action.Receipt) (*action.PoisonReceipt, bool) {
	switch v := r.(type) {
	case *action.PoisonReceipt:
		return v, true
	case action.PoisonReceipt:
		return &v, true
	}
	return nil, false
}

var _ action.Poisoner = (*Poisoner)(nil)

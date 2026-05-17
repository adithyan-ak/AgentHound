// Package module — stateful.go declares the v0.4 StatefulModule sidecar
// interface. Modules that produce per-engagement state (Poisoner receipts,
// Implanter receipts) implement it so `agenthound revert <engagement-id>`
// can walk every module's state directory, read the receipts matching the
// engagement, and dispatch per-module Revert.
//
// On-disk layout — colocated with ~/.agenthound/loot-acknowledged and
// ~/.agenthound/server.token for consistency:
//
//	~/.agenthound/state/<module-id>/<engagement-id>.json
//
// The default helper NewFileStatefulModule wraps file IO with mode 0o600
// on the receipt files and 0o700 on the directories. JSON-encodes a slice
// of receipts (one engagement may produce multiple receipts in a single
// run; later runs append to the same file).
//
// Why a sidecar instead of a Module field: same reason FlagsModule is a
// sidecar — the vast majority of modules ship no per-engagement state
// (Fingerprinter, Looter). Pushing this onto Module would force every
// module to implement no-ops. Sidecar lets V4-Phase 1's Poisoner adopt
// it cleanly without touching every existing collector.
package module

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

// StatefulModule is implemented by destructive-action modules that
// persist receipts. The CLI walks the registry for all StatefulModule
// instances when serving `agenthound revert <engagement-id>`.
type StatefulModule interface {
	// StateDir returns the absolute path to this module's state
	// directory under the AgentHound state root. Implementations should
	// build it via DefaultStateDir(moduleID) so the path is stable
	// across processes.
	StateDir() string

	// WriteReceipt appends r to the engagement-id's receipts file under
	// StateDir(). Returns the absolute path of the written file. The
	// CLI calls this AFTER the Poisoner has successfully applied the
	// mutation, but BEFORE it reports success to the operator — a crash
	// between the HTTP write and the receipt write would otherwise
	// leave a tampered target without a revert path.
	WriteReceipt(engagementID string, r action.Receipt) (path string, err error)

	// ReadReceipts loads every receipt persisted under engagement-id.
	// Used by `agenthound revert` to walk the per-engagement state.
	ReadReceipts(engagementID string) ([]action.Receipt, error)
}

// DefaultStateRoot returns the absolute path to the AgentHound state
// root directory: $HOME/.agenthound/state. Tests override via
// AGENTHOUND_STATE_DIR.
func DefaultStateRoot() (string, error) {
	if override := strings.TrimSpace(os.Getenv("AGENTHOUND_STATE_DIR")); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".agenthound", "state"), nil
}

// DefaultStateDir returns the per-module state directory under the
// state root. The moduleID is sanitized to a filesystem-safe name; we
// also assert that it doesn't escape via "../" because module IDs come
// from module registration, but a future module-loaded-from-disk path
// would otherwise be a directory traversal vector.
func DefaultStateDir(moduleID string) (string, error) {
	root, err := DefaultStateRoot()
	if err != nil {
		return "", err
	}
	if !validModuleID(moduleID) {
		return "", fmt.Errorf("invalid module ID %q (lowercase letters, digits, dot, dash, underscore only)", moduleID)
	}
	return filepath.Join(root, moduleID), nil
}

var moduleIDRE = regexp.MustCompile(`^[a-z0-9._-]+$`)

func validModuleID(id string) bool {
	if id == "" || strings.Contains(id, "..") {
		return false
	}
	return moduleIDRE.MatchString(id)
}

// FileStatefulModule is the default StatefulModule implementation —
// one JSON file per (module-id, engagement-id) tuple, mode 0o600,
// directory mode 0o700. Receipts are stored as a JSON array so
// multiple receipts in a single engagement append cleanly.
type FileStatefulModule struct {
	moduleID  string
	mu        sync.Mutex
	dirCached string
}

// NewFileStatefulModule builds a FileStatefulModule for the given
// module ID. The state dir is created on first WriteReceipt — not at
// construction — so module init() in a process that never poisons
// doesn't pollute the home dir.
func NewFileStatefulModule(moduleID string) *FileStatefulModule {
	return &FileStatefulModule{moduleID: moduleID}
}

func (s *FileStatefulModule) StateDir() string {
	if s.dirCached != "" {
		return s.dirCached
	}
	d, _ := DefaultStateDir(s.moduleID)
	s.dirCached = d
	return d
}

// WriteReceipt persists r under <stateDir>/<engagement-id>.json. When
// the file already exists, the new receipt is appended to the JSON
// array.
//
// Known limitation (v0.4): the in-process mutex protects goroutine
// concurrency but NOT cross-process concurrency. Two separate
// `agenthound poison` processes targeting the same engagement-id can
// race on the read-modify-write cycle (last rename wins, silently
// dropping the other's receipt). The DC35 demo arc is sequential so
// this does not manifest; fix with flock(2) advisory locking is
// tracked for v0.5 before shipping to external operators.
//
// The encoding step is `*action.PoisonReceipt`-aware via type
// assertion, but we accept any action.Receipt so future receipt types
// (ImplantReceipt) work without code changes here. If the receipt is
// not JSON-encodable, the call returns an error rather than silently
// dropping the receipt.
func (s *FileStatefulModule) WriteReceipt(engagementID string, r action.Receipt) (string, error) {
	if !validEngagementID(engagementID) {
		return "", fmt.Errorf("invalid engagement-id %q (alnum, dot, dash, underscore only)", engagementID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := DefaultStateDir(s.moduleID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create state dir: %w", err)
	}
	path := filepath.Join(dir, engagementID+".json")

	existing, _ := readReceiptsFile(path)
	wrapped := receiptEnvelope{
		ModuleID: s.moduleID,
		Type:     receiptTypeFor(r),
		Receipt:  r,
	}
	existing = append(existing, wrapped)

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal receipts: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", fmt.Errorf("write receipts tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("atomic rename: %w", err)
	}
	return path, nil
}

func (s *FileStatefulModule) ReadReceipts(engagementID string) ([]action.Receipt, error) {
	if !validEngagementID(engagementID) {
		return nil, fmt.Errorf("invalid engagement-id %q", engagementID)
	}
	dir, err := DefaultStateDir(s.moduleID)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, engagementID+".json")
	envs, err := readReceiptsFile(path)
	if err != nil {
		return nil, err
	}
	out := make([]action.Receipt, 0, len(envs))
	for _, e := range envs {
		out = append(out, e.Receipt)
	}
	return out, nil
}

// validEngagementID gates engagement-id strings so a hostile operator
// can't path-traverse via `../foo` or shell-inject via spaces. The set
// matches what we expect engagement-ids to look like: e.g. "RTV-2027",
// "DC35-DEMO", "INC-2026.05.17".
var engagementIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func validEngagementID(s string) bool {
	if s == "" || strings.Contains(s, "..") {
		return false
	}
	return engagementIDRE.MatchString(s)
}

// receiptEnvelope is what we serialize. Wrapping the receipt with the
// module-id + a type tag means a future revert path can route the
// concrete receipt to the right module without sniffing fields.
type receiptEnvelope struct {
	ModuleID string         `json:"module_id"`
	Type     string         `json:"type"`
	Receipt  action.Receipt `json:"receipt"`
}

func receiptTypeFor(r action.Receipt) string {
	switch r.(type) {
	case *action.PoisonReceipt, action.PoisonReceipt:
		return "poison"
	case *action.ImplantReceipt, action.ImplantReceipt:
		return "implant"
	default:
		return "unknown"
	}
}

// readReceiptsFile reads and decodes the receipts file. Returns an
// empty slice when the file does not exist (so first WriteReceipt does
// not need a special-case branch).
func readReceiptsFile(path string) ([]receiptEnvelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read receipts: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	// Receipts are stored as a list of envelopes whose Receipt field is
	// a JSON object (the concrete receipt type's fields). We decode
	// into a generic shape, then re-decode the inner receipt as the
	// PoisonReceipt / ImplantReceipt shape.
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode receipts: %w", err)
	}
	out := make([]receiptEnvelope, 0, len(raw))
	for _, r := range raw {
		var e struct {
			ModuleID string          `json:"module_id"`
			Type     string          `json:"type"`
			Receipt  json.RawMessage `json:"receipt"`
		}
		if err := json.Unmarshal(r, &e); err != nil {
			return nil, fmt.Errorf("decode envelope: %w", err)
		}
		var receipt action.Receipt
		switch e.Type {
		case "poison":
			var p action.PoisonReceipt
			if err := json.Unmarshal(e.Receipt, &p); err != nil {
				return nil, fmt.Errorf("decode poison receipt: %w", err)
			}
			receipt = &p
		case "implant":
			var i action.ImplantReceipt
			if err := json.Unmarshal(e.Receipt, &i); err != nil {
				return nil, fmt.Errorf("decode implant receipt: %w", err)
			}
			receipt = &i
		default:
			// Unknown receipt type — preserve as raw map rather than
			// dropping, so a future agenthound version with a new
			// receipt type can decode old state files.
			var m map[string]any
			if err := json.Unmarshal(e.Receipt, &m); err != nil {
				return nil, fmt.Errorf("decode unknown receipt: %w", err)
			}
			receipt = m
		}
		out = append(out, receiptEnvelope{ModuleID: e.ModuleID, Type: e.Type, Receipt: receipt})
	}
	return out, nil
}

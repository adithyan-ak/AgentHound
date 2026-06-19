// Package instructionpoison implements the v0.4 instruction-file Poisoner.
//
// Threat model. Instruction files (CLAUDE.md, AGENTS.md, .cursorrules,
// .github/copilot-instructions.md) are read by AI coding assistants at
// session-init and steer agent behavior across an entire project. An
// attacker who can append a sentinel-bracketed block to such a file
// can inject hidden instructions the operator's developer agent will
// honor on the next prompt.
//
// Why a Poisoner and not an Implanter. The line is: Poisoner modifies
// content the agent CONSUMES (descriptions, instructions). Implanter
// installs persistence (cron, config-server-add). Instruction-file
// modification fits Poisoner cleanly — the agent reads the file as
// part of its prompt, the modification changes that prompt.
//
// Sentinel-bracketed insertion. Unlike the MCP-tool poisoner (which
// captures full original content), this Poisoner only writes between
// two HTML-comment sentinels:
//
//	<!-- agenthound-poison-START engagement=DC35-DEMO -->
//	<injection content>
//	<!-- agenthound-poison-END -->
//
// Revert regex-strips the bracketed block. This is the right shape
// for instruction files because (a) they are expected to grow during
// an engagement (the legitimate developer commits new content) and
// (b) replaying the pre-state would clobber those legitimate edits.
package instructionpoison

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// MaxFileBytes caps the read-and-rewrite size. Instruction files are
// typically <100 KiB; cap at 4 MiB defensively.
const MaxFileBytes int64 = 4 << 20

const (
	sentinelStartFmt = "<!-- agenthound-poison-START engagement=%s -->"
	sentinelEndFmt   = "<!-- agenthound-poison-END engagement=%s -->"
)

// Poisoner is the registered module.
type Poisoner struct {
	stateful module.StatefulModule
}

func New() *Poisoner {
	return &Poisoner{stateful: module.NewFileStatefulModule("instruction.poison")}
}

func (p *Poisoner) Stateful() module.StatefulModule { return p.stateful }
func (p *Poisoner) SetStateful(s module.StatefulModule) {
	p.stateful = s
}

// RegisterFlags satisfies module.FlagsModule. The Implanter-style flags
// here select which file to modify and how to format the bracket — the
// shared poisoner CLI handles --inject and --target-id.
func (p *Poisoner) RegisterFlags(fs *pflag.FlagSet) {
	fs.String("file", "",
		"Absolute path to the instruction file (CLAUDE.md, AGENTS.md, .cursorrules). Required when --type is instruction.file.")
}

// Poison appends (or, when a previous block exists, replaces) a
// sentinel-bracketed injection in the target file.
//
// The "host" Target argument is informational only — instruction-file
// poisoning operates on the local filesystem. Recording it on the
// receipt means an operator can correlate which engagement host the
// modification was tied to without inferring it from --engagement-id
// alone.
func (p *Poisoner) Poison(ctx context.Context, t action.Target, payload action.PoisonPayload) (*action.PoisonReceipt, error) {
	path, _ := payload.Extras["file"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		path = strings.TrimSpace(payload.TargetID)
	}
	if path == "" {
		return nil, errors.New("instruction poison: --file <abs-path> is required")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("instruction poison: --file %q must be an absolute path", path)
	}
	if payload.InjectionContent == "" {
		return nil, errors.New("instruction poison: --inject is required")
	}
	engagementID := payload.EngagementID
	if engagementID == "" {
		return nil, errors.New("instruction poison: --engagement-id is required")
	}

	original, preHash, existed, origMode, err := readFileBounded(path)
	if err != nil {
		return nil, fmt.Errorf("read target file: %w", err)
	}
	// Files this module creates are written 0o600; an existing file keeps
	// its own mode so revert restores exactly what was there before.
	writeMode := origMode
	if !existed {
		writeMode = 0o600
	}

	sentinelStart := fmt.Sprintf(sentinelStartFmt, engagementID)
	sentinelEnd := fmt.Sprintf(sentinelEndFmt, engagementID)

	// Detect any pre-existing block from a prior poison of this
	// engagement-id. If found, REPLACE it so re-running poison on the
	// same engagement cleanly overwrites rather than nesting blocks.
	updated, hadPrior := stripBracket(original, sentinelStart, sentinelEnd)
	block := buildBlock(sentinelStart, sentinelEnd, payload.InjectionContent)

	// The block contract is: it always begins with "\n" + sentinelStart
	// and ends with sentinelEnd + "\n". When the existing content does
	// NOT end with a newline, we promote the leading "\n" into a "\n"
	// separator on the file boundary; otherwise the existing trailing
	// newline IS the separator and we don't add a second one. Either
	// way, revert can identify the bracket span deterministically by
	// matching from the sentinelStart line through the sentinelEnd line.
	var final string
	if updated == "" || strings.HasSuffix(updated, "\n") {
		final = updated + block
	} else {
		final = updated + "\n" + block
	}

	postHash := sha256Hex([]byte(final))

	receipt := &action.PoisonReceipt{
		ModuleID:        "instruction.poison",
		EngagementID:    engagementID,
		Target:          t,
		TargetID:        path,
		OriginalContent: "", // unused — sentinel strip is the revert primitive
		InjectedContent: payload.InjectionContent,
		Mode:            "sentinel-bracket",
		AppliedAt:       time.Now().UTC(),
		DryRun:          payload.DryRun,
		Extra: map[string]any{
			"file":           path,
			"sentinel_start": sentinelStart,
			"sentinel_end":   sentinelEnd,
			"pre_sha256":     preHash,
			"post_sha256":    postHash,
			"replaced_prior": hadPrior,
			"file_existed":   existed,
			"orig_mode":      modeStr(writeMode),
		},
	}

	if payload.DryRun {
		slog.Info("instruction poison dry-run",
			"file", path,
			"engagement_id", engagementID,
			"replaced_prior", hadPrior)
		return receipt, nil
	}

	if _, err := p.stateful.WriteReceipt(engagementID, receipt); err != nil {
		return nil, fmt.Errorf("persist receipt before mutation: %w", err)
	}

	if err := writeFileAtomic(path, []byte(final), writeMode); err != nil {
		return nil, fmt.Errorf("write poisoned file: %w", err)
	}
	slog.Info("instruction poison applied",
		"file", path,
		"engagement_id", engagementID,
		"original_bytes", len(original),
		"final_bytes", len(final),
		"replaced_prior", hadPrior)
	return receipt, nil
}

// Revert strips the sentinel-bracketed block from the target file. If
// the file no longer contains the bracket (operator already restored
// out-of-band, or another revert ran), Revert is a no-op.
//
// We compare PreSHA256 against the post-strip hash and warn (do not
// fail) if they differ — that signals legitimate edits between the
// poison and the revert, which is normal during an engagement.
func (p *Poisoner) Revert(ctx context.Context, receipt action.Receipt) error {
	r, ok := normalizeReceipt(receipt)
	if !ok {
		return fmt.Errorf("instruction poison revert: unexpected receipt type %T", receipt)
	}
	if r.DryRun {
		return nil
	}
	path, _ := r.Extra["file"].(string)
	if path == "" {
		return errors.New("instruction poison revert: receipt missing 'file'")
	}
	sentinelStart, _ := r.Extra["sentinel_start"].(string)
	sentinelEnd, _ := r.Extra["sentinel_end"].(string)
	if sentinelStart == "" || sentinelEnd == "" {
		return errors.New("instruction poison revert: receipt missing sentinel markers")
	}
	prePoisonHash, _ := r.Extra["pre_sha256"].(string)
	// file_existed defaults to true for receipts written before this
	// field existed — the safe choice, since the old behavior always
	// left a file behind. We only remove on revert when we KNOW poison
	// created the file.
	fileExisted := true
	if v, ok := r.Extra["file_existed"].(bool); ok {
		fileExisted = v
	}
	origMode := parseMode(r.Extra["orig_mode"], 0o600)

	current, _, _, _, err := readFileBounded(path)
	if err != nil {
		return fmt.Errorf("read target file: %w", err)
	}
	stripped, hadBlock := stripBracket(current, sentinelStart, sentinelEnd)
	if !hadBlock {
		slog.Info("instruction poison revert: target already clean (no-op)",
			"file", path,
			"engagement_id", r.EngagementID)
		return nil
	}
	// If poison created this file and stripping our block leaves it
	// empty, remove it to restore the original absent state. If the
	// strip left content behind (legitimate edits the operator made),
	// keep the file — deleting it would destroy their work.
	if !fileExisted && stripped == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove poison-created file: %w", err)
		}
		slog.Info("instruction poison revert: removed poison-created file",
			"file", path,
			"engagement_id", r.EngagementID)
		return nil
	}
	if err := writeFileAtomic(path, []byte(stripped), origMode); err != nil {
		return fmt.Errorf("write reverted file: %w", err)
	}
	postRevertHash := sha256Hex([]byte(stripped))
	if prePoisonHash != "" && postRevertHash != prePoisonHash {
		slog.Warn("instruction poison revert: post-revert hash differs from pre-poison hash (legitimate edits detected — operator should review)",
			"file", path,
			"engagement_id", r.EngagementID,
			"pre_poison_sha256", prePoisonHash,
			"post_revert_sha256", postRevertHash)
	}
	return nil
}

// readFileBounded reads up to MaxFileBytes from path. Returns content,
// SHA-256 hex, whether the file existed, its permission bits, and any
// error. A missing file is NOT an error — we return empty content with
// existed=false and let the caller decide. Instruction files often
// don't exist before the engagement plants them; we want poison to
// create the file rather than refuse.
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

// writeFileAtomic writes data via temp+rename to defeat partial-write
// states, applying mode exactly (chmod after write to bypass umask).
// Callers pass the original file's mode so revert restores the prior
// permissions; for files this module creates, the caller passes 0o600
// because instruction files often live under user home directories and
// we don't want to widen world-readability.
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

// modeStr/parseMode persist a file mode through the receipt's JSON Extra
// map as an octal string, sidestepping the float64 coercion JSON applies
// to numeric values when a receipt is read back from disk for revert.
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

// stripBracket removes the sentinel-bracketed block. Symmetric with
// buildBlock — every bracket we write begins with sentinelStart on its
// own line and ends with sentinelEnd on its own line. The block
// includes a trailing newline; revert strips through that trailing
// newline. We do NOT strip the leading newline of the file ahead of
// the block — that newline either preexisted the bracket (legitimate
// content) or was added as a separator at poison time.
//
// Concretely: we look for `sentinelStart` and walk forward to the next
// `sentinelEnd` plus any single trailing newline. The block is bounded
// from startIdx (where sentinelStart begins) to endIdx (after the
// trailing newline of the sentinelEnd line). Anything outside that
// span is preserved verbatim — so legitimate edits made to the file
// AFTER the block during the engagement land back unchanged.
//
// If the bracket was preceded by a separator newline that the
// poisoner added (because the file did not end with a newline before
// poison), the post-strip file simply ends with that newline now —
// indistinguishable from a manually-saved file. Operators don't need
// it removed.
func stripBracket(content, start, end string) (string, bool) {
	startIdx := strings.Index(content, start)
	if startIdx < 0 {
		return content, false
	}
	endRel := strings.Index(content[startIdx:], end)
	if endRel < 0 {
		// Corrupted file — sentinelStart without sentinelEnd. Don't
		// guess; operator must inspect.
		return content, false
	}
	endIdx := startIdx + endRel + len(end)
	// Strip a single trailing newline produced at write time.
	if endIdx < len(content) && content[endIdx] == '\n' {
		endIdx++
	}
	return content[:startIdx] + content[endIdx:], true
}

// buildBlock returns the bracket block. Always ends with a trailing
// newline so revert's strip rule (sentinelEnd + optional `\n`) is
// deterministic.
func buildBlock(start, end, body string) string {
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return start + "\n" + body + end + "\n"
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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

// Package cli — revert.go is the v0.4 entry point for rolling back any
// destructive action this machine applied under a given engagement-id.
//
// CLI shape:
//
//	agenthound revert <engagement-id>
//
// Behavior. Walks every registered module that exposes a
// StatefulModule via the standard `Stateful() module.StatefulModule`
// shape, reads the engagement's receipt file, and dispatches per-module
// Revert for each receipt.
//
// Per-file LIFO. Each module's receipt file is append-ordered (oldest
// first). Revert walks each file newest-first so repeated mutations of
// the same target unwind in reverse: for two sequential poisons A→B then
// B→C, reverting C→B before B→A restores A. Reverting oldest-first would
// instead hit the conflict-aware guard (current C matches neither the
// first receipt's original A nor its injected B) and refuse to write.
// Ordering is per (module, engagement) — the same scope as the receipt
// file's advisory lock — not a global sequence across modules.
//
// Conflict-aware partial retries use each receipt's live-state checks. A fully
// completed stacked rollback is not universally replay-idempotent because
// immutable receipts carry no completion state; an older restored state may
// correctly conflict with the newest receipt on a later full replay.
//
// Failure handling. Reverters must never blind-write: a Revert that
// cannot confirm the current state (re-read failure) or finds a
// third-party change returns an error rather than overwriting. Any such
// error is collected, the receipts are RETAINED (never deleted), and the
// command exits nonzero. We report a clean rollback only when every
// receipt reverted or was already clean — a partial rollback is reported
// as INCOMPLETE so the operator can investigate and re-run.
//
// The CLI does NOT delete receipts after a successful revert — they
// are the durable audit trail for the engagement. Operators clean up
// out-of-band when an engagement closes.
package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

// perReceiptRevertTimeout bounds each individual Revert dispatch so one
// unresponsive target cannot wedge the whole cleanup. Reverters that talk
// HTTP (mcppoison) may issue a tools/list read plus a write, each under
// their own ~30s client timeout, so 90s leaves headroom; file-scoped
// reverters return near-instantly and never approach it.
const perReceiptRevertTimeout = 90 * time.Second

var revertCmd = &cobra.Command{
	Use:   "revert <engagement-id>",
	Short: "Roll back every destructive action recorded for an engagement",
	Long: `Walk every module's state directory, read receipts whose engagement-id
matches the argument, and dispatch per-module Revert.

Retries are conflict-aware: Reverters check current target state before writing.
Receipts remain immutable, so replaying an already-completed stacked rollback is
not guaranteed to be a no-op and may conservatively report a conflict.

Dry-run receipts (poison without --commit) are no-ops.

Example:

  agenthound revert DC35-DEMO

Receipts are persisted under ~/.agenthound/state/<module-id>/<engagement-id>.json
and are NOT deleted after revert — they are the audit trail.`,
	Args: cobra.ExactArgs(1),
	RunE: runRevert,
}

func init() {
	revertCmd.Flags().String("auth-token", "",
		"Bearer token for authenticated targets. Passed to Reverter via context (not stored on disk).")
	rootCmd.AddCommand(revertCmd)
}

// statefulModule is the shape Poisoner / Implanter modules expose to
// give the revert verb access to their persisted receipts. We use a
// structural interface (no SDK type) so a future module that doesn't
// embed FileStatefulModule can still participate by satisfying the
// shape.
type statefulModule interface {
	Stateful() module.StatefulModule
}

func runRevert(cmd *cobra.Command, args []string) error {
	engagementID := strings.TrimSpace(args[0])
	if engagementID == "" {
		return errors.New("revert: engagement-id is required")
	}

	authToken, _ := cmd.Flags().GetString("auth-token")

	// Cleanup runs on a non-cancellable base context: derive from
	// context.Background() (NEVER cmd.Context()) so a Ctrl-C that cancels
	// the command's own context does not tear down an in-flight rollback
	// and strand a half-reverted target. Each Revert call is bounded
	// individually (perReceiptRevertTimeout) so the run still cannot hang
	// forever on an unresponsive endpoint.
	baseCtx := context.Background()
	if authToken != "" {
		baseCtx = context.WithValue(baseCtx, action.RevertAuthTokenKey{}, authToken)
	}
	mods := module.List()

	var (
		totalRead     int
		totalReverted int
		totalSkipped  int
		errs          []string
	)

	for _, mod := range mods {
		sm, ok := mod.(statefulModule)
		if !ok {
			continue
		}
		state := sm.Stateful()
		if state == nil {
			continue
		}

		receipts, err := state.ReadReceipts(engagementID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: read receipts: %v", mod.ID(), err))
			continue
		}
		if len(receipts) == 0 {
			continue
		}
		reverter, ok := mod.(action.Reverter)
		if !ok {
			errs = append(errs, fmt.Sprintf("%s: %d receipt(s) but module is not a Reverter", mod.ID(), len(receipts)))
			continue
		}

		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[revert] %s — %d receipt(s) for engagement %s (newest first)\n",
			mod.ID(), len(receipts), engagementID)

		// Per-file LIFO: walk this module's append-ordered receipts
		// newest-first so repeated same-target mutations unwind in
		// reverse. #N is the receipt's position in the file, so the
		// printed order counts down (visibly LIFO).
		for i := len(receipts) - 1; i >= 0; i-- {
			r := receipts[i]
			totalRead++
			// Skip dry-run receipts to keep the operator-facing output
			// honest about what actually rolled back.
			if isDryRun(r) {
				totalSkipped++
				_, _ = fmt.Fprintf(cmd.OutOrStderr(),
					"[revert]   #%d: dry-run receipt — no-op\n", i+1)
				continue
			}
			if err := revertReceipt(baseCtx, reverter, r); err != nil {
				errs = append(errs, fmt.Sprintf("%s receipt #%d: %v", mod.ID(), i+1, err))
				_, _ = fmt.Fprintf(cmd.OutOrStderr(),
					"[revert]   #%d: FAILED — %v\n", i+1, err)
				continue
			}
			totalReverted++
			_, _ = fmt.Fprintf(cmd.OutOrStderr(),
				"[revert]   #%d: reverted\n", i+1)
		}
	}

	// Only report a clean rollback when nothing failed. A conflict or an
	// indeterminate re-read surfaces as an error here; the receipts stay
	// on disk (we never delete them) so the operator can investigate and
	// re-run, and the command exits nonzero.
	if len(errs) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[revert] INCOMPLETE — %d reverted, %d dry-run skipped, %d failed (of %d total receipts); receipts retained for retry\n",
			totalReverted, totalSkipped, len(errs), totalRead)
		return fmt.Errorf("revert had %d error(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	_, _ = fmt.Fprintf(cmd.OutOrStderr(),
		"[revert] complete — %d reverted, %d dry-run skipped, 0 failed (of %d total receipts)\n",
		totalReverted, totalSkipped, totalRead)
	return nil
}

// revertReceipt dispatches a single rollback under a bounded, non-
// cancellable context. baseCtx carries the optional auth token and is
// derived from context.Background(); the per-call timeout is the only
// cancellation source, so a rollback in progress runs to completion or
// times out cleanly rather than being interrupted mid-write.
func revertReceipt(baseCtx context.Context, reverter action.Reverter, r action.Receipt) error {
	ctx, cancel := context.WithTimeout(baseCtx, perReceiptRevertTimeout)
	defer cancel()
	return reverter.Revert(ctx, r)
}

// isDryRun checks both pointer and value forms of the known receipt
// types. Unknown receipt types default to "not dry-run" so the
// reverter still gets a chance to handle them — better to attempt and
// have the module's Revert() short-circuit than to silently skip.
func isDryRun(r action.Receipt) bool {
	switch v := r.(type) {
	case *action.PoisonReceipt:
		return v != nil && v.DryRun
	case action.PoisonReceipt:
		return v.DryRun
	case *action.ImplantReceipt:
		return v != nil && v.DryRun
	case action.ImplantReceipt:
		return v.DryRun
	}
	return false
}

type runScopedReceipt struct {
	sequence uint64
	receipt  action.Receipt
	reverter action.Reverter
}

// cleanupCampaignRun is the authoritative campaign cleanup path. It selects
// one exact engagement+run across every registered stateful module, validates
// globally unique positive invocation sequences before writing anything, then
// fail-stops in descending sequence order. Receipts are never changed or
// removed.
func cleanupCampaignRun(
	ctx context.Context,
	engagementID string,
	campaignRunID string,
) campaign.CleanupExecution {
	if strings.TrimSpace(engagementID) == "" || strings.TrimSpace(campaignRunID) == "" {
		return campaign.CleanupExecution{
			Status: campaign.CleanupIndeterminate, FailureCode: "scope_missing",
		}
	}

	selected := make([]runScopedReceipt, 0)
	sequences := make(map[uint64]bool)
	for _, mod := range module.List() {
		stateful, ok := mod.(statefulModule)
		if !ok || stateful.Stateful() == nil {
			continue
		}
		receipts, err := stateful.Stateful().ReadReceipts(engagementID)
		if err != nil {
			return campaign.CleanupExecution{
				Status: campaign.CleanupIndeterminate, ReceiptsRetained: true,
				FailureCode: "receipt_read_failed",
			}
		}
		for _, receipt := range receipts {
			receiptEngagement, runID, sequence, known := receiptRunMetadata(receipt)
			if !known || runID != campaignRunID {
				continue
			}
			if receiptEngagement != engagementID || sequence == 0 || sequences[sequence] {
				return campaign.CleanupExecution{
					Status: campaign.CleanupIndeterminate, ReceiptsRetained: true,
					FailureCode: "invalid_sequence_metadata",
				}
			}
			reverter, ok := mod.(action.Reverter)
			if !ok {
				return campaign.CleanupExecution{
					Status: campaign.CleanupIndeterminate, ReceiptsRetained: true,
					FailureCode: "reverter_missing",
				}
			}
			sequences[sequence] = true
			selected = append(selected, runScopedReceipt{
				sequence: sequence, receipt: receipt, reverter: reverter,
			})
		}
	}
	if len(selected) == 0 {
		return campaign.CleanupExecution{
			Status: campaign.CleanupIndeterminate, FailureCode: "receipt_missing",
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].sequence > selected[j].sequence
	})
	for _, item := range selected {
		if !isDryRun(item.receipt) {
			if err := campaign.ConsumeMutation(ctx); err != nil {
				return campaign.CleanupExecution{
					Status:           campaign.CleanupIndeterminate,
					ReceiptsSelected: len(selected), ReceiptsRetained: true,
					FailureCode: "mutation_budget",
				}
			}
		}
		if err := item.reverter.Revert(ctx, item.receipt); err != nil {
			status := campaign.CleanupFailed
			switch {
			case errors.Is(err, action.ErrRevertConflict):
				status = campaign.CleanupConflict
			case errors.Is(err, action.ErrRevertIndeterminate),
				errors.Is(err, context.DeadlineExceeded),
				errors.Is(err, context.Canceled):
				status = campaign.CleanupIndeterminate
			}
			return campaign.CleanupExecution{
				Status: status, ReceiptsSelected: len(selected), ReceiptsRetained: true,
				FailureCode: "revert_failed",
			}
		}
	}
	return campaign.CleanupExecution{
		Status:           campaign.CleanupRestored,
		ReceiptsSelected: len(selected), ReceiptsRetained: true,
	}
}

func receiptRunMetadata(receipt action.Receipt) (
	engagementID string,
	campaignRunID string,
	stepSequence uint64,
	known bool,
) {
	switch value := receipt.(type) {
	case *action.PoisonReceipt:
		if value == nil {
			return "", "", 0, false
		}
		return value.EngagementID, value.CampaignRunID, value.StepSequence, true
	case action.PoisonReceipt:
		return value.EngagementID, value.CampaignRunID, value.StepSequence, true
	case *action.ImplantReceipt:
		if value == nil {
			return "", "", 0, false
		}
		return value.EngagementID, value.CampaignRunID, value.StepSequence, true
	case action.ImplantReceipt:
		return value.EngagementID, value.CampaignRunID, value.StepSequence, true
	default:
		return "", "", 0, false
	}
}

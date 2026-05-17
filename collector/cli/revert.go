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
// Revert for each receipt. Idempotent — already-reverted receipts
// surface as no-ops (the Poisoner's Revert checks current state before
// writing). Receipts with DryRun=true are also no-ops.
//
// The CLI does NOT delete receipts after a successful revert — they
// are the durable audit trail for the engagement. Operators clean up
// out-of-band when an engagement closes.
package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

var revertCmd = &cobra.Command{
	Use:   "revert <engagement-id>",
	Short: "Roll back every destructive action recorded for an engagement",
	Long: `Walk every module's state directory, read receipts whose engagement-id
matches the argument, and dispatch per-module Revert.

Idempotent: re-running 'agenthound revert <id>' against an already-
reverted engagement is safe — Reverters check current target state
before writing.

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
	ctx := context.Background()
	if authToken != "" {
		ctx = context.WithValue(ctx, action.RevertAuthTokenKey{}, authToken)
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
			"[revert] %s — %d receipt(s) for engagement %s\n",
			mod.ID(), len(receipts), engagementID)

		for i, r := range receipts {
			totalRead++
			// Skip dry-run receipts to keep the operator-facing output
			// honest about what actually rolled back.
			if isDryRun(r) {
				totalSkipped++
				_, _ = fmt.Fprintf(cmd.OutOrStderr(),
					"[revert]   #%d: dry-run receipt — no-op\n", i+1)
				continue
			}
			if err := reverter.Revert(ctx, r); err != nil {
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

	_, _ = fmt.Fprintf(cmd.OutOrStderr(),
		"[revert] complete — %d reverted, %d dry-run skipped, %d errored (of %d total receipts)\n",
		totalReverted, totalSkipped, len(errs), totalRead)

	if len(errs) > 0 {
		return fmt.Errorf("revert had %d error(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return nil
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

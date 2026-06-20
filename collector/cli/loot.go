package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// lootCmd is the v0.2 entry point for the `loot` action. It dispatches
// to a registered Looter via module.GetByTarget(--type, action.Loot)
// and writes the resulting ingest envelope to --output (or stdout via
// --output -). v0.2 ships with one Looter (LiteLLM) registered at
// modules/litellmloot; --type litellm resolves to it.
//
// Safety controls (per docs/plans/v0.2-implementation.md decision C):
//   - First-run AUTHORIZED interactive prompt + ~/.agenthound/loot-acknowledged
//     sentinel so the operator confirms once that they have authorization.
//     Subsequent invocations skip the prompt.
//   - --engagement-id <ID> is recorded on every emitted edge's evidence map
//     and surfaces in slog output, giving the operator's IR notification a
//     stable correlation key.
//   - --include-credential-values is OFF by default — emitted Credential
//     nodes carry value_hash but not the raw value.
var lootCmd = &cobra.Command{
	Use:   "loot <host>",
	Short: "Extract latent secrets from a discovered service (read-only)",
	Long: `Run a registered Looter against a known service endpoint.

Looters are read-only by contract: they make no state-mutating requests.
GET / HEAD is the norm; a few use idempotent, side-effect-free search or
lookup POSTs that some APIs expose only via POST (e.g. MLflow runs/search,
Ollama /api/show) — these read without changing target state, and each is
guarded by a get_only regression test. The action emits Credential nodes
and EXPOSES_CREDENTIAL edges into the graph, where the
cross_service_credential_chain post-processor joins them with Config
Collector emissions to surface credential-chain findings.

Supported Looters include --type litellm (LiteLLM gateway), ollama,
jupyter, and mlflow.

Example:

  agenthound loot 172.20.0.10:4000 --type litellm \
      --master-key sk-... --engagement-id RTV-DEMO --output -

The --master-key flag is sugar for --credential master_key=sk-... — the
generic flag works for every future Looter without per-module wiring.`,
	Args: cobra.ExactArgs(1),
	RunE: runLoot,
}

func init() {
	lootCmd.Flags().String("type", "", "Looter target kind (e.g. 'litellm', 'ollama'). Required.")
	lootCmd.Flags().String("master-key", "", "Master key for the target service. Sugar for --credential master_key=...")
	lootCmd.Flags().StringSlice("credential", nil, "Operator-supplied credential as KEY=VALUE (repeatable)")
	lootCmd.Flags().Bool("include-credential-values", false,
		"Include raw credential values on emitted Credential nodes. Default: only value_hash is emitted.")
	lootCmd.Flags().Int("max-items", 0, "Cap emitted Credential nodes per category (0 = use looter default)")
	lootCmd.Flags().String("engagement-id", "",
		"Engagement identifier recorded on every emitted edge's evidence map. Coordinate with target IR.")
	lootCmd.Flags().Duration("timeout", 0, "Per-probe HTTP timeout (0 = looter default)")
	if err := lootCmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}
	// v0.3: Looters that satisfy module.FlagsModule contribute per-module
	// flags. Resolution at command-construction time (here, via every
	// registered Looter) keeps `loot --help` listing all per-module flags
	// regardless of --type, so the operator discovers them. Dispatch-time
	// (runLoot) resolution would require --type before --help, which is
	// unfriendly. Per-module flag namespaces don't collide today; if they
	// ever do, we'll add a per-target prefix.
	for _, mod := range module.ListByAction(action.Loot) {
		module.RegisterFlagsFor(lootCmd, mod)
	}
	rootCmd.AddCommand(lootCmd)
}

func runLoot(cmd *cobra.Command, args []string) error {
	target := args[0]
	kind, _ := cmd.Flags().GetString("type")
	masterKey, _ := cmd.Flags().GetString("master-key")
	credSpecs, _ := cmd.Flags().GetStringSlice("credential")
	includeValues, _ := cmd.Flags().GetBool("include-credential-values")
	maxItems, _ := cmd.Flags().GetInt("max-items")
	engagementID, _ := cmd.Flags().GetString("engagement-id")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	output, _ := cmd.Flags().GetString("scan-output")
	if output == "" {
		if cfg != nil && cfg.Output != "" {
			output = cfg.Output
		} else if v, _ := cmd.Root().PersistentFlags().GetString("output"); v != "" {
			output = v
		}
	}

	creds := map[string]string{}
	for _, spec := range credSpecs {
		k, v, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("invalid --credential %q: expected KEY=VALUE", spec)
		}
		creds[k] = v
	}
	if masterKey != "" {
		creds["master_key"] = masterKey
	}

	// First-invocation AUTHORIZED prompt. The sentinel file
	// (~/.agenthound/loot-acknowledged) lets us skip this on subsequent
	// runs — the operator only needs to confirm once per machine.
	if err := requireLootAcknowledged(cmd.OutOrStderr(), cmd.InOrStdin()); err != nil {
		return err
	}

	mod, ok := module.GetByTarget(kind, action.Loot)
	if !ok {
		return fmt.Errorf("no looter registered for --type %q", kind)
	}
	looter, ok := mod.(action.Looter)
	if !ok {
		return fmt.Errorf("registered module %q is not a Looter", mod.ID())
	}

	// Per-module flag values flow into LootOptions.Extras. Only flags the
	// resolved Looter declared via FlagsModule.RegisterFlags reach the
	// looter — we walk the module's own pflag.FlagSet to discover them
	// rather than dumping every command flag (which would leak --type,
	// --output, etc. into Extras).
	extras := collectModuleExtras(cmd, mod)

	ctx := context.Background()
	res, err := looter.Loot(ctx, action.Target{
		Kind:    "host",
		Address: target,
	}, action.LootOptions{
		Credentials:             creds,
		MaxItems:                maxItems,
		Timeout:                 timeout,
		IncludeCredentialValues: includeValues,
		EngagementID:            engagementID,
		Extras:                  extras,
	})
	if err != nil {
		return fmt.Errorf("loot: %w", err)
	}

	envelope := buildLootEnvelope(target, kind, engagementID, res)

	_, _ = fmt.Fprintf(cmd.OutOrStderr(),
		"[loot] %s %s — credentials_found=%d, partial_failures=%d\n",
		kind, target, res.Summary.CredentialsFound, res.Summary.PartialFailures)
	for _, pe := range res.PartialErrors {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[loot]   partial: %s\n", pe)
	}

	if output == "" {
		output = fmt.Sprintf("loot-%s.json", envelope.Meta.ScanID)
	}
	if output == "-" {
		return writeCollectorOutputStdout(envelope)
	}
	return writeCollectorOutput(envelope, output)
}

// buildLootEnvelope wraps the Looter's IngestData in a top-level scan
// envelope so the server's ingest endpoint accepts it through the same
// path as collector scans. The watermark records the loot type and
// engagement-id for downstream correlation.
func buildLootEnvelope(target, kind, engagementID string, res *action.LootResult) *ingest.IngestData {
	scanID := uuid.New().String()
	env := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        "scan",
			CollectorVersion: "0.2.0-dev",
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			ScanID:           scanID,
			Extra: map[string]any{
				"loot_type":      kind,
				"loot_target":    target,
				"engagement_id":  engagementID,
				"partial_errors": res.PartialErrors,
			},
		},
	}
	if res.IngestData != nil {
		env.Graph.Nodes = res.IngestData.Graph.Nodes
		env.Graph.Edges = res.IngestData.Graph.Edges
	}
	return env
}

// requireLootAcknowledged checks for ~/.agenthound/loot-acknowledged.
// If absent, prints the legal/OPSEC warning and prompts the operator
// to type AUTHORIZED. Writes the sentinel on success so subsequent
// invocations skip the prompt.
func requireLootAcknowledged(stderr io.Writer, stdin io.Reader) error {
	sentinel, err := lootSentinelPath()
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		return nil
	}
	_, _ = fmt.Fprintln(stderr)
	_, _ = fmt.Fprintln(stderr, "[loot] First loot invocation on this machine.")
	_, _ = fmt.Fprintln(stderr, "[loot] Looters extract credentials from running services. They are read-only —")
	_, _ = fmt.Fprintln(stderr, "[loot] no state-mutating HTTP methods — but every probe shows up in the target's audit")
	_, _ = fmt.Fprintln(stderr, "[loot] log. Coordinate with the target's IR/security team out-of-band BEFORE")
	_, _ = fmt.Fprintln(stderr, "[loot] running this against any production system. See https://docs.agenthound.io/operator/loot/litellm/.")
	_, _ = fmt.Fprint(stderr, "[loot] If you have authorization for this engagement, type AUTHORIZED to proceed: ")
	r := bufio.NewReader(stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read authorization prompt: %w", err)
	}
	if strings.TrimSpace(line) != "AUTHORIZED" {
		return errors.New("authorization not confirmed; aborting loot")
	}
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o700); err != nil {
		return fmt.Errorf("create sentinel dir: %w", err)
	}
	contents, _ := json.Marshal(map[string]any{
		"acknowledged_at": time.Now().UTC().Format(time.RFC3339),
		"warning":         "Looters are read-only. Coordinate with target IR before each engagement.",
	})
	if err := os.WriteFile(sentinel, contents, 0o600); err != nil {
		slog.Warn("failed to write loot sentinel; will re-prompt next run", "error", err)
	}
	_, _ = fmt.Fprintln(stderr, "[loot] authorization confirmed; proceeding")
	return nil
}

// lootSentinelPath resolves to $HOME/.agenthound/loot-acknowledged.
// Mirrors server.token's location for consistency.
func lootSentinelPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".agenthound", "loot-acknowledged"), nil
}

// collectModuleExtras walks the per-module flag surface (the flags the
// resolved Looter contributed via FlagsModule.RegisterFlags) and pulls
// their typed values off the cobra command's FlagSet. The returned map
// is what LootOptions.Extras carries into the looter — looters read with
// type assertions, never panicking on missing keys.
//
// We can't just dump every flag on lootCmd because the persistent root
// flags (--output, --log-level, etc.) and the loot-level flags (--type,
// --master-key) would leak in. We isolate the per-module surface by
// running RegisterFlags against a sandboxed FlagSet purely for
// introspection — that gives us the exact flag-name list each module
// owns.
func collectModuleExtras(cmd *cobra.Command, m module.Module) map[string]any {
	fm, ok := m.(module.FlagsModule)
	if !ok {
		return nil
	}
	probe := pflag.NewFlagSet("loot-module-introspect", pflag.ContinueOnError)
	fm.RegisterFlags(probe)
	out := map[string]any{}
	probe.VisitAll(func(f *pflag.Flag) {
		// Pull the value the operator actually supplied off the command's
		// merged FlagSet. f.Value carries the type-aware getter.
		live := cmd.Flags().Lookup(f.Name)
		if live == nil {
			return
		}
		switch f.Value.Type() {
		case "bool":
			b, err := cmd.Flags().GetBool(f.Name)
			if err == nil {
				out[f.Name] = b
			}
		case "string":
			s, err := cmd.Flags().GetString(f.Name)
			if err == nil {
				out[f.Name] = s
			}
		case "int":
			i, err := cmd.Flags().GetInt(f.Name)
			if err == nil {
				out[f.Name] = i
			}
		default:
			out[f.Name] = live.Value.String()
		}
	})
	return out
}

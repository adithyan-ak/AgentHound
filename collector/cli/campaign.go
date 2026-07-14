// Package cli — campaign.go is the entry point for the predicted-to-verified
// campaign runner.
//
// CLI shape:
//
//	agenthound campaign <host> --scenario cred-reach \
//	    --witness witness.json \
//	    --engagement-id <ID> \
//	    [--commit] [--insecure] [--timeout 30s] \
//	    [--credential-env AGENTHOUND_CAMPAIGN_CREDENTIAL | --credential-stdin]
//
// Design:
//
//  1. --commit=false is the DEFAULT. Without it the scenario plans only —
//     it never probes the target and never emits evidence (dry run).
//  2. AUTHORIZED prompt + ~/.agenthound/campaign-acknowledged sentinel, mirroring
//     the poison/extract gates. When stdin is consumed by --witness -/
//     --credential-stdin, acknowledge non-interactively via a pre-existing
//     sentinel or AGENTHOUND_CAMPAIGN_AUTHORIZED=AUTHORIZED.
//  3. Credential material is supplied OUT OF BAND via an env var (default) or
//     stdin — NEVER a flag (flags leak into process listings / shell history).
//     The scenario hashes it locally against the exported value_hash and never
//     logs or serializes the raw value.
//  4. Emissions ride the existing "scan" collector envelope, exactly like
//     extract.go's buildExtractEnvelope, under a deterministic coverage domain so
//     a valid negative retires the prior verification.
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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const defaultCredentialEnv = "AGENTHOUND_CAMPAIGN_CREDENTIAL"

var campaignCmd = &cobra.Command{
	Use:   "campaign <host>",
	Short: "Run an ordered, evidence-producing campaign scenario against a known service",
	Long: `Run a registered campaign scenario that verifies a predicted graph
relationship with observed evidence, or validates a reversible target
mutation end to end.

The runner ships two scenarios:

cred-reach — a READ-ONLY differential credential-reach oracle. Given a
server-exported witness for a predicted CAN_REACH / credential-chain
finding, it reads the exact predicted MCP resource once WITHOUT
authentication (control) and once WITH a hash-matched credential
(authed), then classifies the pair:

  control denied at initialize/read + exact auth read allowed -> credential_gated_reach_verified
  both allowed                  -> anonymous_access_observed
  unauth allowed + auth denied  -> anonymous_access_observed (+ credential_rejected)
  both exact resource reads denied -> not_observed (retires this agent's prior verification)
  404 / malformed / timeout / … -> indeterminate (prior evidence preserved)

It mutates nothing, so it needs no rollback. Credential material is
supplied out of band (env var or stdin) and hash-matched locally; the raw
value is never logged or written to the graph. A hash-only credential (no
executable material) is not runnable.

mcp-poison-roundtrip — a STANDALONE target-mutation validation. It
applies an operator-authorized mcppoison mutation, re-reads the exact
injected state (the ORACLE), issues the conflict-aware revert, and
re-reads to confirm the original is restored (the CLEANUP). The oracle
and cleanup outcomes are reported SEPARATELY. It is NOT an attack finding
and makes NO claim about a predicted credential path — it validates only
that the reversible mutation machinery works against this target. It
takes --target-id / --inject (and optional --mode / --update-method /
--update-path / --list-path / --auth-token) instead of a witness.

By default --commit is OFF: the scenario plans only. Pass --commit only
when you have authorization for this engagement.

Examples:

  agenthound-server witness --finding <id> > witness.json            # export (server)
  export AGENTHOUND_CAMPAIGN_CREDENTIAL='sk-...'                      # out-of-band material
  agenthound campaign https://mcp.example/mcp --scenario cred-reach \
      --witness witness.json --engagement-id DC35-DEMO --commit --output -

  agenthound campaign https://mcp.example/mcp --scenario mcp-poison-roundtrip \
      --target-id support_lookup --inject "TEST MUTATION" \
      --engagement-id DC35-DEMO --commit

See https://docs.agenthound.io/operator/offensive-actions/ for the full guide.`,
	Args:          cobra.ExactArgs(1),
	RunE:          runCampaign,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func init() {
	campaignCmd.Flags().String("scenario", "", "Scenario ID to run (e.g. 'cred-reach', 'mcp-poison-roundtrip'). Required.")
	campaignCmd.Flags().String("witness", "", "Path to the server-exported witness JSON, or '-' for stdin. Required for witness-based scenarios (cred-reach).")
	campaignCmd.Flags().String("engagement-id", "", "Engagement identifier. Required.")
	campaignCmd.Flags().Bool("commit", false, "Execute the scenario and emit evidence. Default: dry-run (plan only).")
	campaignCmd.Flags().Bool("insecure", false, "Skip TLS certificate verification for the probes. Default: verify.")
	campaignCmd.Flags().Duration("timeout", 30*time.Second, "Total forward scenario elapsed-time limit.")
	campaignCmd.Flags().String("credential-env", defaultCredentialEnv, "Environment variable holding the out-of-band credential material.")
	campaignCmd.Flags().Bool("credential-stdin", false, "Read the credential material from stdin instead of an env var.")
	// Mutation parameters for the mcp-poison-roundtrip scenario (ignored by
	// witness-based scenarios). They mirror the `agenthound poison` per-module
	// flags so the STANDALONE target-mutation validation is driven the same way.
	campaignCmd.Flags().String("target-id", "", "[mcp-poison-roundtrip] MCP tool whose description is mutated then restored.")
	campaignCmd.Flags().String("inject", "", "[mcp-poison-roundtrip] Injection content applied then conflict-aware reverted.")
	campaignCmd.Flags().String("mode", "", "[mcp-poison-roundtrip] Injection mode: replace|append|prepend (default replace).")
	campaignCmd.Flags().String("update-method", "", "[mcp-poison-roundtrip] HTTP method for the tool-description write (default PUT).")
	campaignCmd.Flags().String("update-path", "", "[mcp-poison-roundtrip] Path template for the write; {id} is the target tool (default /admin/tools/{id}).")
	campaignCmd.Flags().String("list-path", "", "[mcp-poison-roundtrip] JSON-RPC tools/list path (default /).")
	campaignCmd.Flags().String("auth-token", "", "[mcp-poison-roundtrip] Optional bearer token for the target admin surface.")
	if err := campaignCmd.MarkFlagRequired("scenario"); err != nil {
		panic(err)
	}
	if err := campaignCmd.MarkFlagRequired("engagement-id"); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(campaignCmd)
}

func runCampaign(cmd *cobra.Command, args []string) error {
	host := args[0]
	targetRef := campaign.SanitizedTargetReference(host)
	scenarioID, _ := cmd.Flags().GetString("scenario")
	engagementID, _ := cmd.Flags().GetString("engagement-id")
	commit, _ := cmd.Flags().GetBool("commit")
	insecure, _ := cmd.Flags().GetBool("insecure")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	scenario, ok := campaign.Get(scenarioID)
	if !ok {
		available := make([]string, 0)
		for _, s := range campaign.List() {
			available = append(available, s.ID())
		}
		return fmt.Errorf("campaign: no scenario registered for --scenario %q (available: %s)",
			scenarioID, strings.Join(available, ", "))
	}

	stdin := cmd.InOrStdin()
	in := campaign.RunInput{
		Host:         host,
		EngagementID: engagementID,
		Insecure:     insecure,
		Commit:       commit,
		Timeout:      timeout,
	}

	// Witness-based scenarios (cred-reach) resolve a witness + out-of-band
	// credential material. Scenarios that opt out via RequiresWitness()=false
	// (the mcppoison round-trip) take mutation parameters from flags instead —
	// no witness, no credential material.
	stdinConsumed := false
	if scenarioRequiresWitness(scenario) {
		witnessPath, _ := cmd.Flags().GetString("witness")
		if strings.TrimSpace(witnessPath) == "" {
			return fmt.Errorf("campaign: --witness is required for scenario %q", scenario.ID())
		}
		credentialEnv, _ := cmd.Flags().GetString("credential-env")
		credentialStdin, _ := cmd.Flags().GetBool("credential-stdin")
		witnessFromStdin := witnessPath == "-"
		if witnessFromStdin && credentialStdin {
			return errors.New("campaign: cannot read both --witness - and --credential-stdin from stdin; use a --witness file or --credential-env")
		}
		witness, err := resolveWitness(witnessPath, stdin)
		if err != nil {
			return err
		}
		material, err := resolveCredentialMaterial(credentialStdin, credentialEnv, stdin)
		if err != nil {
			return err
		}
		in.Witness = witness
		in.CredentialMaterial = material
		stdinConsumed = witnessFromStdin || credentialStdin
	} else {
		in.Params = campaignMutationParams(cmd)
		authToken := in.Params["auth-token"]
		in.CleanupRun = func(
			ctx context.Context,
			engagementID string,
			campaignRunID string,
		) campaign.CleanupExecution {
			if authToken != "" {
				ctx = context.WithValue(ctx, action.RevertAuthTokenKey{}, authToken)
			}
			return cleanupCampaignRun(ctx, engagementID, campaignRunID)
		}
	}

	if err := requireCampaignAcknowledged(cmd.OutOrStderr(), stdin, stdinConsumed); err != nil {
		return err
	}
	if commit && scenarioRequiresMutationConsent(scenario) {
		if err := requirePoisonAcknowledged(cmd.OutOrStderr(), stdin); err != nil {
			return fmt.Errorf("campaign: destructive acknowledgement: %w", err)
		}
	}

	res, err := scenario.Run(cmd.Context(), in)
	if res != nil && res.Report != nil {
		if reportErr := writeCampaignReport(cmd.OutOrStderr(), res.Report); reportErr != nil {
			return reportErr
		}
	}
	if err != nil {
		if errors.Is(err, campaign.ErrNotRunnable) {
			_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[campaign] NOT RUNNABLE: %v\n", err)
		}
		return fmt.Errorf("campaign: %w", err)
	}

	if res.DryRun {
		if res.TargetRef != "" {
			targetRef = res.TargetRef
		}
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[campaign] DRY-RUN %s on %s\n", scenario.ID(), targetRef)
		_, _ = fmt.Fprint(cmd.OutOrStderr(), res.Plan)
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[campaign] re-run with --commit to execute.\n")
		return nil
	}

	// STANDALONE target-mutation validation: report the oracle and cleanup
	// outcomes separately. No differential graph evidence is emitted — the
	// round-trip evidence stays in the campaign transport, never a scored edge
	// or finding.
	if res.Report != nil && res.Report.Standalone {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[campaign] COMMITTED %s on %s (STANDALONE target-mutation validation) — %s\n",
			scenario.ID(), targetRef, res.Report.Summary())
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStderr(),
		"[campaign] COMMITTED %s on %s — outcome=%s control=%s authed=%s\n",
		scenario.ID(), targetRef, res.Outcome, res.ControlStatus, res.AuthedStatus)

	envelope := buildCampaignEnvelope(scenario.ID(), scenario.Version(), engagementID, res.Evidence)

	output := resolveCampaignOutput(cmd)
	if output == "" {
		output = fmt.Sprintf("campaign-%s.json", envelope.Meta.ScanID)
	}
	if output == "-" {
		return writeCollectorOutputStdout(envelope)
	}
	return writeCollectorOutput(envelope, output)
}

func scenarioRequiresMutationConsent(s campaign.Scenario) bool {
	required, ok := s.(interface{ RequiresMutationConsent() bool })
	return ok && required.RequiresMutationConsent()
}

func writeCampaignReport(w io.Writer, report *campaign.RunReport) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("campaign: encode run report: %w", err)
	}
	if _, err := fmt.Fprintf(w, "[campaign] RUN_REPORT %s\n", encoded); err != nil {
		return fmt.Errorf("campaign: write run report: %w", err)
	}
	return nil
}

// scenarioRequiresWitness reports whether a scenario consumes a credential-reach
// witness. Scenarios may opt out via an optional RequiresWitness() bool method
// (the mcppoison round-trip does); those that don't implement it default to
// requiring a witness, matching the cred-reach behavior.
func scenarioRequiresWitness(s campaign.Scenario) bool {
	if wr, ok := s.(interface{ RequiresWitness() bool }); ok {
		return wr.RequiresWitness()
	}
	return true
}

// campaignMutationParams collects the mutation parameters for a non-witness
// scenario (the mcppoison round-trip) from flags. Empty values are passed
// through so the scenario applies its own defaults; required-field validation is
// the scenario's job (it reports precondition failures).
func campaignMutationParams(cmd *cobra.Command) map[string]string {
	get := func(name string) string {
		v, _ := cmd.Flags().GetString(name)
		return v
	}
	return map[string]string{
		"target-id":     get("target-id"),
		"inject":        get("inject"),
		"mode":          get("mode"),
		"update-method": get("update-method"),
		"update-path":   get("update-path"),
		"list-path":     get("list-path"),
		"auth-token":    get("auth-token"),
	}
}

// resolveWitness reads and strictly decodes the witness. Unknown fields are
// rejected so a malformed or tampered witness is caught early.
func resolveWitness(path string, stdin io.Reader) (campaign.Witness, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return campaign.Witness{}, fmt.Errorf("campaign: read witness: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var w campaign.Witness
	if err := dec.Decode(&w); err != nil {
		return campaign.Witness{}, fmt.Errorf("campaign: parse witness: %w", err)
	}
	return w, nil
}

// resolveCredentialMaterial reads the out-of-band credential material from stdin
// or the named env var. It returns the material unchanged (may be empty; the
// scenario precondition rejects empty/mismatched material as not-runnable).
func resolveCredentialMaterial(fromStdin bool, envName string, stdin io.Reader) (string, error) {
	if fromStdin {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("campaign: read credential from stdin: %w", err)
		}
		// Trim a single trailing newline (the shell/pipe artifact) without
		// stripping interior bytes of the secret.
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	if strings.TrimSpace(envName) == "" {
		envName = defaultCredentialEnv
	}
	return os.Getenv(envName), nil
}

// buildCampaignEnvelope wraps the scenario's evidence in a "scan"-collector
// ingest envelope, mirroring extract.go's buildExtractEnvelope. The coverage
// domain is deterministic on (scenario id/version, agent, credential, server, resource)
// — excluding run id / timestamp / outcome — so a later valid negative under the
// same domain retires the prior verification. Non-definitive (indeterminate)
// outcomes are marked partial so the domain is NOT promoted and prior evidence
// is preserved.
func buildCampaignEnvelope(scenarioID string, scenarioVersion int, engagementID string, ev *campaign.Evidence) *ingest.IngestData {
	scanID := uuid.New().String()
	env := common.NewIngestData("scan", scanID)
	env.Meta.CollectorVersion = common.CollectorVersion
	env.Meta.Extra = map[string]any{
		"campaign_scenario":         scenarioID,
		"campaign_scenario_version": scenarioVersion,
		"engagement_id":             engagementID,
		"campaign_outcome":          string(ev.Outcome),
		"campaign_run_id":           ev.RunID,
	}

	w := ev.Witness
	coverageKey := ingest.CanonicalCoverageKey("scan", "campaign", campaignCoverageScope(scenarioID, scenarioVersion, w))

	state := ingest.OutcomeComplete
	if !ev.Outcome.Definitive() {
		state = ingest.OutcomePartial
	}

	nodes, edges := ev.EvidenceGraph(scanID)

	env.Meta.Collection = &ingest.CollectionReport{
		State:        state,
		CoverageKeys: []string{coverageKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "scan",
			CoverageKey: coverageKey,
			Target:      w.ServerID,
			Method:      "campaign:" + scenarioID,
			State:       state,
			Items:       len(edges),
		}},
	}

	env.Graph.Nodes = nodes
	env.Graph.Edges = edges
	if env.Graph.Nodes == nil {
		env.Graph.Nodes = []ingest.Node{}
	}
	if env.Graph.Edges == nil {
		env.Graph.Edges = []ingest.Edge{}
	}
	ingest.TagObservationDomain(&env.Graph, coverageKey)
	return env
}

// campaignCoverageScope is the deterministic coverage domain identity: scenario
// id/version + agent ID + credential ID + server ID + resource ID. It deliberately excludes
// run id, timestamps, outcome, finding id, and any secret.
func campaignCoverageScope(scenarioID string, scenarioVersion int, w campaign.Witness) string {
	return strings.Join([]string{
		scenarioID,
		strconv.Itoa(scenarioVersion),
		w.AgentID,
		w.CredentialID,
		w.ServerID,
		w.ResourceID,
	}, "\x00")
}

func resolveCampaignOutput(cmd *cobra.Command) string {
	if cfg != nil && cfg.Output != "" {
		return cfg.Output
	}
	if v, _ := cmd.Root().PersistentFlags().GetString("output"); v != "" {
		return v
	}
	return ""
}

// requireCampaignAcknowledged is the campaign authorization gate. It mirrors the
// poison/extract gates but supports non-interactive acknowledgment when stdin is
// consumed by --witness -/--credential-stdin.
func requireCampaignAcknowledged(stderr io.Writer, stdin io.Reader, stdinConsumed bool) error {
	sentinel, err := campaignSentinelPath()
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		return nil
	}
	if strings.TrimSpace(os.Getenv("AGENTHOUND_CAMPAIGN_AUTHORIZED")) == "AUTHORIZED" {
		writeCampaignSentinel(sentinel, stderr)
		return nil
	}
	if stdinConsumed {
		return errors.New(
			"campaign: authorization required but stdin is consumed by --witness -/--credential-stdin; " +
				"set AGENTHOUND_CAMPAIGN_AUTHORIZED=AUTHORIZED or run once interactively to create the sentinel")
	}
	_, _ = fmt.Fprintln(stderr)
	_, _ = fmt.Fprintln(stderr, "[campaign] First campaign invocation on this machine.")
	_, _ = fmt.Fprintln(stderr, "[campaign] Campaign scenarios actively probe a target service to verify a")
	_, _ = fmt.Fprintln(stderr, "[campaign] predicted relationship. The cred-reach scenario is READ-ONLY (it")
	_, _ = fmt.Fprintln(stderr, "[campaign] reads the exact predicted resource and mutates nothing), but it")
	_, _ = fmt.Fprintln(stderr, "[campaign] still sends live requests using supplied credential material.")
	_, _ = fmt.Fprintln(stderr, "[campaign]")
	_, _ = fmt.Fprintln(stderr, "[campaign] CFAA / Computer Misuse Act / equivalent laws apply. Do NOT run against")
	_, _ = fmt.Fprintln(stderr, "[campaign] systems you do not have written authorization to test.")
	_, _ = fmt.Fprint(stderr, "[campaign] If you have authorization for this engagement, type AUTHORIZED to proceed: ")
	r := bufio.NewReader(stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read authorization prompt: %w", err)
	}
	if strings.TrimSpace(line) != "AUTHORIZED" {
		return errors.New("authorization not confirmed; aborting campaign")
	}
	writeCampaignSentinel(sentinel, stderr)
	_, _ = fmt.Fprintln(stderr, "[campaign] authorization confirmed; proceeding")
	return nil
}

func writeCampaignSentinel(sentinel string, stderr io.Writer) {
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "[campaign] warning: create sentinel dir: %v\n", err)
		return
	}
	contents, _ := json.Marshal(map[string]any{
		"acknowledged_at": time.Now().UTC().Format(time.RFC3339),
		"warning":         "Campaign scenarios send live probes to the target. cred-reach is read-only but uses supplied credential material.",
	})
	if err := os.WriteFile(sentinel, contents, 0o600); err != nil {
		slog.Warn("failed to write campaign sentinel; will re-prompt next run", "error", err)
	}
}

func campaignSentinelPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".agenthound", "campaign-acknowledged"), nil
}

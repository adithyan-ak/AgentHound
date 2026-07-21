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

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
	"github.com/google/uuid"
)

var extractCmd = &cobra.Command{
	Use:   "extract <source-node-id>",
	Short: "Extract training signals or derived artifacts from a model (gated)",
	Long: `Run a registered Extractor against a locally-available artifact.

The embedding-invert Extractor detects fine-tune training
signals by analyzing statistical outliers in the embedding layer of a
GGUF weight file. Point --artifact at any GGUF the operator has already
obtained out-of-band: a blob copied from ~/.ollama/models/blobs/ on a
compromised host, a HuggingFace download, or any other source. The
Ollama HTTP API does not expose a raw-weight download endpoint, so
AgentHound cannot pull the file itself.

By default --commit is OFF. Without --commit the Extractor runs end-to-
end but does not emit ingest data (dry-run summary only).

Example:

  agenthound extract <ai-model-node-id> --type embedding-invert \
      --artifact /path/to/support-agent-v3.gguf \
      --commit --engagement-id DC35-DEMO --output -`,
	Args:          cobra.ExactArgs(1),
	RunE:          runExtract,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func init() {
	extractCmd.Flags().String("type", "", "Extractor target kind (e.g. 'embedding-invert'). Required.")
	extractCmd.Flags().String("artifact", "", "Path to the local artifact file (e.g. a GGUF weight file obtained out-of-band).")
	extractCmd.Flags().Bool("commit", false, "Emit ingest data. Default: dry-run summary only.")
	extractCmd.Flags().String("engagement-id", "", "Engagement identifier. Required.")
	if err := extractCmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}
	if err := extractCmd.MarkFlagRequired("engagement-id"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(extractCmd)
}

func runExtract(cmd *cobra.Command, args []string) error {
	sourceNodeID := args[0]
	if !ingest.IsCanonicalNodeID(sourceNodeID) {
		return errors.New(
			"extract: <source-node-id> must be sha256: followed by 64 lowercase hexadecimal characters",
		)
	}
	kind, _ := cmd.Flags().GetString("type")
	artifactPath, _ := cmd.Flags().GetString("artifact")
	commit, _ := cmd.Flags().GetBool("commit")
	engagementID, _ := cmd.Flags().GetString("engagement-id")
	var origin ingest.CollectionOrigin
	if commit {
		var err error
		origin, err = requireCollectionOrigin()
		if err != nil {
			return err
		}
	}

	if artifactPath == "" {
		return errors.New("extract: --artifact <path> is required")
	}

	if err := requireExtractAcknowledged(cmd.OutOrStderr(), cmd.InOrStdin()); err != nil {
		return err
	}

	mod, ok := module.GetByTarget(kind, action.Extract)
	if !ok {
		return fmt.Errorf("no extractor registered for --type %q", kind)
	}
	extractor, ok := mod.(action.Extractor)
	if !ok {
		return fmt.Errorf("registered module %q is not an Extractor", mod.ID())
	}

	extras := collectModuleExtras(cmd, mod)

	ctx := context.Background()
	res, err := extractor.Extract(ctx, action.Target{
		Kind:    "node",
		Address: sourceNodeID,
	}, action.ExtractOptions{
		SourceNodeID: sourceNodeID,
		ArtifactPath: artifactPath,
		EngagementID: engagementID,
		DryRun:       !commit,
		Extras:       extras,
	})
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	if commit && res.IngestData != nil {
		output, _ := cmd.Flags().GetString("scan-output")
		if output == "" {
			if cfg != nil && cfg.Output != "" {
				output = cfg.Output
			} else if v, _ := cmd.Root().PersistentFlags().GetString("output"); v != "" {
				output = v
			}
		}
		envelope := buildExtractEnvelope(origin, sourceNodeID, kind, engagementID, res)
		if output == "" {
			output = fmt.Sprintf("extract-%s.json", envelope.Meta.ScanID)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[extract] COMMITTED %s — artifacts=%d confidence=%.2f\n",
			kind, res.Summary.ArtifactsProduced, res.Summary.Confidence)
		if output == "-" {
			return writeCollectorOutputStdout(envelope)
		}
		return writeCollectorOutput(envelope, output)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStderr(),
		"[extract] DRY-RUN %s — artifacts=%d confidence=%.2f\n",
		kind, res.Summary.ArtifactsProduced, res.Summary.Confidence)
	if !commit {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[extract] re-run with --commit to emit ingest data.\n")
	}
	return nil
}

func buildExtractEnvelope(origin ingest.CollectionOrigin, sourceNodeID, kind, engagementID string, res *action.ExtractResult) *ingest.IngestData {
	scanID := uuid.New().String()
	env := common.NewIngestData("scan", scanID)
	env.Meta.Origin = origin
	env.Meta.Extra = map[string]any{
		"extract_type":   kind,
		"source_node_id": sourceNodeID,
		"engagement_id":  engagementID,
	}
	coverageKey := ingest.CanonicalCoverageKey(
		"scan",
		"extract",
		kind+"\x00"+sourceNodeID,
	)
	env.Meta.Collection = &ingest.CollectionReport{
		State:        ingest.OutcomeComplete,
		CoverageKeys: []string{coverageKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "scan",
			CoverageKey: coverageKey,
			Target:      sourceNodeID,
			Method:      "extract:" + kind,
			State:       ingest.OutcomeComplete,
			Items:       res.Summary.ArtifactsProduced,
		}},
	}
	if res.IngestData != nil {
		env.Graph = res.IngestData.Graph
	}
	if env.Graph.Nodes == nil {
		env.Graph.Nodes = []ingest.Node{}
	}
	if env.Graph.Edges == nil {
		env.Graph.Edges = []ingest.Edge{}
	}
	ingest.TagObservationDomain(&env.Graph, coverageKey)
	return env
}

func requireExtractAcknowledged(stderr io.Writer, stdin io.Reader) error {
	sentinel, err := extractSentinelPath()
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		return nil
	}
	_, _ = fmt.Fprintln(stderr)
	_, _ = fmt.Fprintln(stderr, "[extract] First extract invocation on this machine.")
	_, _ = fmt.Fprintln(stderr, "[extract] Extractors analyze model artifacts to recover training signals.")
	_, _ = fmt.Fprintln(stderr, "[extract] This may reveal proprietary training data or fine-tune content.")
	_, _ = fmt.Fprint(stderr, "[extract] If you have authorization, type AUTHORIZED to proceed: ")
	r := bufio.NewReader(stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read authorization prompt: %w", err)
	}
	if strings.TrimSpace(line) != "AUTHORIZED" {
		return errors.New("authorization not confirmed; aborting extract")
	}
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o700); err != nil {
		return fmt.Errorf("create sentinel dir: %w", err)
	}
	contents, _ := json.Marshal(map[string]any{
		"acknowledged_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err := os.WriteFile(sentinel, contents, 0o600); err != nil {
		slog.Warn("failed to write extract sentinel", "error", err)
	}
	_, _ = fmt.Fprintln(stderr, "[extract] authorization confirmed; proceeding")
	return nil
}

func extractSentinelPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".agenthound", "extract-acknowledged"), nil
}

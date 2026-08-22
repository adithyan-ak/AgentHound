package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/contact"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const perReceiptRevertTimeout = 90 * time.Second

var revertCmd = &cobra.Command{
	Use:   "revert <scan.json>",
	Short: "Retry unresolved recovery records in a scan artifact",
	Args:  cobra.ExactArgs(1),
	RunE:  runRevert,
}

func init() { rootCmd.AddCommand(revertCmd) }

func runRevert(cmd *cobra.Command, args []string) error {
	path := strings.TrimSpace(args[0])
	if path == "" {
		return errors.New("revert: scan artifact path is required")
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("revert: read %s: %w", path, err)
	}
	version, err := ingest.DecodeVersion(document)
	if err != nil {
		return fmt.Errorf("revert: decode artifact envelope: %w", err)
	}
	if version != ingest.CurrentVersion {
		return fmt.Errorf("revert: artifact version %d is unsupported", version)
	}
	var artifact ingest.IngestData
	if err := ingest.DecodeStrict(bytes.NewReader(document), &artifact); err != nil {
		return fmt.Errorf("revert: strict artifact decode: %w", err)
	}
	if artifact.Meta.Type != ingest.IngestType || artifact.Meta.Collector != "scan" {
		return errors.New("revert: input is not an AgentHound scan artifact")
	}
	execution, present, err := ingest.GetScanExecution(artifact.Meta)
	if err != nil {
		return fmt.Errorf("revert: decode scan execution: %w", err)
	}
	if !present {
		return errors.New("revert: artifact has no scan_execution recovery state")
	}
	policy, err := contact.NewPolicy(execution.Exclusions)
	if err != nil {
		return err
	}
	runtime := &scanRuntime{
		cmd: cmd, ctx: cmd.Context(), policy: policy, artifact: &artifact,
		execution: execution, output: path, completed: make(map[string]bool), printed: make(map[string]bool),
		deep: execution.Deep, stealth: execution.Mode == ingest.ScanModeStealth,
	}
	if err := runtime.retryUnresolvedRecovery(); err != nil {
		return fmt.Errorf("revert incomplete: %w", err)
	}
	if execution.Summary.CleanupFailures != 0 {
		return fmt.Errorf("revert incomplete: %d recovery record(s) remain unresolved", execution.Summary.CleanupFailures)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[revert] all recovery records restored in %s\n", path)
	return nil
}

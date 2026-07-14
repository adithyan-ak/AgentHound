package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/projection"
)

var witnessCmd = &cobra.Command{
	Use:   "witness",
	Short: "Export a sanitized campaign witness for a predicted CAN_REACH finding",
	Long: `Export a stable, sanitized witness for a predicted credential-gated
CAN_REACH finding so the collector-side campaign runner can verify it.

The witness is a content-addressed tuple — credential/server/resource node
IDs, the credential value_hash + merge_key, the predicted edge kind, the
ordered path topology, and the publication/schema revision. It contains NO
Neo4j relationship IDs, NO arbitrary node properties, and NO secrets. It is
built under a guarded read of the published projection, so it reflects a
stable, published prediction.

Pass the witness to the collector:

  agenthound-server witness --finding <id> > witness.json
  agenthound campaign <host> --scenario cred-reach --witness witness.json \
      --engagement-id <ID> --commit`,
	RunE:          runWitness,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func init() {
	witnessCmd.Flags().String("finding", "", "Finding ID (16-char fingerprint) to export a witness for. Required.")
	witnessCmd.Flags().String("output", "-", "Write the witness JSON to this path, or '-' for stdout.")
	if err := witnessCmd.MarkFlagRequired("finding"); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(witnessCmd)
}

func runWitness(cmd *cobra.Command, _ []string) error {
	findingID, _ := cmd.Flags().GetString("finding")
	output, _ := cmd.Flags().GetString("output")

	ctx := context.Background()
	infra, cleanup, err := Bootstrap(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	witness, identity, err := projection.GuardedRead(
		ctx,
		infra.FindingStore,
		func() (*campaign.Witness, error) {
			return analysis.BuildWitness(ctx, infra.GraphDB, findingID)
		},
	)
	if err != nil {
		return fmt.Errorf("witness export: %w", err)
	}
	witness.PublicationRevision = int(identity.Revision)
	if err := witness.Validate(); err != nil {
		return fmt.Errorf("witness export: %w", err)
	}

	data, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		return fmt.Errorf("witness export: marshal: %w", err)
	}
	if output == "" || output == "-" {
		fmt.Println(string(data))
		return nil
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		return fmt.Errorf("witness export: write %s: %w", output, err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "witness written to %s (published revision %d)\n", output, identity.Revision)
	return nil
}

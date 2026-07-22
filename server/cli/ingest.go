package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/spf13/cobra"
)

var ingestCmd = &cobra.Command{
	Use:   "ingest <file.json | ->",
	Short: "Ingest collector JSON output into the graph database",
	Long: `Ingest collector JSON into the graph database.

Provide a path to a collector JSON file, or '-' to read from stdin. The
stdin form is the standard pipe target for 'agenthound scan --output -':

  agenthound scan --output - | agenthound-server ingest -
  ssh target 'agenthound scan --output -' | agenthound-server ingest -`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		filePath := args[0]

		var data []byte
		var err error
		if filePath == "-" {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
		} else {
			data, err = os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
		}

		var ingestData ingest.IngestData
		if err := ingest.DecodeStrict(bytes.NewReader(data), &ingestData); err != nil {
			return fmt.Errorf("parse JSON: %w", err)
		}

		infra, cleanup, err := Bootstrap(ctx)
		if err != nil {
			return err
		}
		defer cleanup()

		result, ingestErr := infra.Pipeline.Ingest(ctx, &ingestData)
		return finishIngestCommand(cmd.OutOrStdout(), result, ingestErr)
	},
}

func finishIngestCommand(
	w io.Writer,
	result *ingest.IngestResult,
	ingestErr error,
) error {
	var resultErr error
	if result != nil {
		resultErr = writeIngestResult(w, result)
	}
	if ingestErr != nil {
		// A write-stage failure can return a useful typed result and the original
		// pipeline error together. The result renderer is expected to classify
		// that result as incomplete; preserve the pipeline error as the command's
		// cause after rendering its committed row counts and failed stage.
		return fmt.Errorf("ingest: %w", ingestErr)
	}
	if result == nil {
		return fmt.Errorf("ingest returned no result")
	}
	return resultErr
}

func writeIngestResult(w io.Writer, result *ingest.IngestResult) error {
	if result == nil {
		return fmt.Errorf("ingest returned no result")
	}

	complete := result.Outcome == ingest.OutcomeComplete &&
		result.ProjectionStatus == model.ProjectionComplete &&
		result.PublishedRevision != nil
	heading := "Ingest incomplete"
	if result.Outcome == ingest.OutcomeFailed {
		heading = "Ingest failed"
	} else if complete {
		heading = "Ingest complete"
	}

	lines := []string{
		fmt.Sprintf("%s:\n", heading),
		fmt.Sprintf("  Scan ID:            %s\n", result.ScanID),
		fmt.Sprintf("  Outcome:            %s\n", result.Outcome),
		fmt.Sprintf("  Projection status:  %s\n", result.ProjectionStatus),
		fmt.Sprintf("  Collection point:   %s (%s, %s)\n", collectionPointDisplay(result.Identity), result.Identity.Quality, result.Identity.Recognition),
		fmt.Sprintf("  Collection point ID: %s\n", result.Identity.CollectionPointID),
		fmt.Sprintf("  Network context:    %s (%s, %s)\n", result.Identity.NetworkContextID, result.Identity.NetworkClass, result.Identity.NetworkQuality),
	}
	if result.PublishedRevision != nil {
		lines = append(lines, fmt.Sprintf("  Published revision: %d\n", *result.PublishedRevision))
	} else {
		lines = append(lines, "  Published revision: unavailable\n")
	}
	lines = append(lines,
		fmt.Sprintf("  Node write rows:    %d\n", result.WriteRows.Nodes),
		fmt.Sprintf("  Edge write rows:    %d\n", result.WriteRows.Edges),
		fmt.Sprintf("  Duration:           %s\n", result.Duration),
	)
	if len(result.Warnings) > 0 {
		lines = append(lines, fmt.Sprintf("  Warnings:           %d\n", len(result.Warnings)))
		for _, warning := range result.Warnings {
			slog.Warn(warning)
		}
	}
	if _, err := io.WriteString(w, strings.Join(lines, "")); err != nil {
		return fmt.Errorf("write ingest result: %w", err)
	}

	if complete {
		return nil
	}

	detail := "result outcome or projection is incomplete"
	if result.PublishedRevision == nil {
		detail = "publication revision unavailable"
	}
	for _, stage := range result.Stages {
		if !stage.Required {
			continue
		}
		if stage.Error != "" || stage.State == ingest.OutcomePartial ||
			stage.State == ingest.OutcomeFailed || stage.State == ingest.OutcomeTruncated ||
			stage.State == ingest.OutcomeUnknown {
			detail = fmt.Sprintf("stage %s=%s", stage.Name, stage.State)
			if stage.Error != "" {
				detail += ": " + conciseIngestError(stage.Error)
			}
			break
		}
	}

	return fmt.Errorf(
		"ingest did not publish a complete projection: outcome=%s projection=%s; %s",
		result.Outcome,
		result.ProjectionStatus,
		detail,
	)
}

func collectionPointDisplay(identity ingest.IngestIdentityResult) string {
	label := identity.Display.Hostname
	if label == "" {
		const prefix = "sha256:"
		digest := strings.TrimPrefix(identity.CollectionPointID, prefix)
		if len(digest) > 8 {
			digest = digest[:8]
		}
		label = "Point " + digest
	}
	platform := strings.TrimSpace(identity.Display.OS + " " + identity.Display.Architecture)
	if platform != "" {
		label += " · " + platform
	}
	return label
}

func conciseIngestError(message string) string {
	const maxRunes = 240
	runes := []rune(message)
	if len(runes) <= maxRunes {
		return message
	}
	return string(runes[:maxRunes]) + "…"
}

func init() {
	rootCmd.AddCommand(ingestCmd)
}

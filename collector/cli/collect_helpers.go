package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func writeCollectorOutput(data *ingest.IngestData, outputPath string) error {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	if outputPath == "" {
		_, err = os.Stdout.Write(encoded)
		if err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		fmt.Println()
		return nil
	}

	if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	slog.Info("output written", "path", outputPath, "nodes", len(data.Graph.Nodes), "edges", len(data.Graph.Edges))
	return nil
}

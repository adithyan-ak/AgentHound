package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

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

	if err := writeOutputAtomic(outputPath, encoded); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	slog.Info("output written", "path", outputPath, "nodes", len(data.Graph.Nodes), "edges", len(data.Graph.Edges))
	_, _ = fmt.Fprintf(os.Stderr, "Next: agenthound-server ingest %s\n", outputPath)
	return nil
}

// writeOutputAtomic writes data to path via a temp file in the same directory
// followed by os.Rename. A SIGINT or crash mid-write cannot leave a half-written
// file at path. The temp file is chmod'd to 0o600 (POSIX; on NTFS this is a no-op
// and the file inherits the directory's NTFS ACL — see docs/security.md).
func writeOutputAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".agenthound-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if rename never happens.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

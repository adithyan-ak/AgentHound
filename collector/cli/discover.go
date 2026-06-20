// Package cli — discover.go implements the v0.3 `agenthound discover <CIDR>`
// verb, the protocol-discovery counterpart to `agenthound scan`. Where scan
// surveys AI-service ports (Ollama, vLLM, …) for fingerprintable services,
// discover probes per-protocol shapes — JSON-RPC initialize for MCP, the
// well-known A2A agent-card endpoint for A2A — and emits MCPServer / A2AAgent
// nodes as ingest envelope output.
//
// Safety controls are identical to scan.go (--allow-public-targets, the
// AUTHORIZED prompt, --authorization-file watermark) so an operator who
// learned the scan flow doesn't need to re-learn discover. Both verbs flow
// through the same network expansion code in modules/networkscan/expand.go.
package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/modules/protoscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

var discoverCmd = &cobra.Command{
	Use:   "discover <cidr|host|@file>",
	Short: "Discover MCP servers and A2A agents on a network (protocol probes)",
	Long: `Run protocol-shape probes against a CIDR or single host to discover
MCP servers (JSON-RPC initialize) and A2A agents (well-known agent-card).

Unlike 'agenthound scan', which sweeps a fixed AI-service port set and
fingerprints each open port, 'agenthound discover' issues protocol-specific
HTTP probes against likely web ports (3000/8000/8080/8443 for MCP,
80/443/3000/8080 for A2A) and emits :MCPServer and :A2AAgent nodes for each
positive match.

Example:

    agenthound discover 10.0.0.0/24 --output -

Public-IP targets require --allow-public-targets and an interactive
AUTHORIZED prompt — same gates as 'scan'. See https://docs.agenthound.io/operator/discover/.`,
	Args: cobra.ExactArgs(1),
	RunE: runDiscover,
}

func init() {
	discoverCmd.Flags().Bool("mcp", false, "Probe for MCP servers (default: both)")
	discoverCmd.Flags().Bool("a2a", false, "Probe for A2A agents (default: both)")
	discoverCmd.Flags().IntSlice("mcp-ports", nil, "Override MCP probe port set (default: 3000,8000,8080,8443)")
	discoverCmd.Flags().IntSlice("a2a-ports", nil, "Override A2A probe port set (default: 80,443,3000,8080)")
	discoverCmd.Flags().Int("network-scan-concurrency", protoscan.DefaultConcurrency, "Max parallel HTTP probes")
	discoverCmd.Flags().Duration("timeout", protoscan.DefaultProbeTimeout, "Per-probe HTTP timeout")
	discoverCmd.Flags().Bool("insecure", false, "Skip TLS verification on HTTPS probes")
	discoverCmd.Flags().Bool("allow-public-targets", false, "Allow probing public IP space (requires AUTHORIZED prompt)")
	discoverCmd.Flags().Bool("allow-large-cidr", false, "Allow probing CIDRs larger than /16")
	discoverCmd.Flags().String("authorization-file", "", "Path to a written-authorization document; recorded in the watermark")
	discoverCmd.Flags().String("scan-output", "", "Write ingest JSON to this path. Use '-' for stdout.")
	rootCmd.AddCommand(discoverCmd)
}

func runDiscover(cmd *cobra.Command, args []string) error {
	spec := args[0]
	probeMCP, _ := cmd.Flags().GetBool("mcp")
	probeA2A, _ := cmd.Flags().GetBool("a2a")
	mcpPorts, _ := cmd.Flags().GetIntSlice("mcp-ports")
	a2aPorts, _ := cmd.Flags().GetIntSlice("a2a-ports")
	concurrency, _ := cmd.Flags().GetInt("network-scan-concurrency")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	insecure, _ := cmd.Flags().GetBool("insecure")
	allowPublic, _ := cmd.Flags().GetBool("allow-public-targets")
	allowLarge, _ := cmd.Flags().GetBool("allow-large-cidr")
	authzFile, _ := cmd.Flags().GetString("authorization-file")
	output, _ := cmd.Flags().GetString("scan-output")
	if output == "" {
		if cfg != nil && cfg.Output != "" {
			output = cfg.Output
		} else if v, _ := cmd.Root().PersistentFlags().GetString("output"); v != "" {
			output = v
		}
	}

	// Default both modes when neither flag set, mirroring `scan`.
	if !probeMCP && !probeA2A {
		probeMCP = true
		probeA2A = true
	}

	if allowPublic {
		if err := requireAuthorizedPrompt(spec, cmd.OutOrStderr(), cmd.InOrStdin()); err != nil {
			return err
		}
	}

	var authzHash string
	if authzFile != "" {
		hash, err := sha256OfFile(authzFile)
		if err != nil {
			return fmt.Errorf("--authorization-file %s: %w", authzFile, err)
		}
		authzHash = hash
	}

	mode := protoscan.ModeBoth
	switch {
	case probeMCP && !probeA2A:
		mode = protoscan.ModeMCP
	case !probeMCP && probeA2A:
		mode = protoscan.ModeA2A
	}

	scanner := &protoscan.Scanner{
		Mode:        mode,
		MCPPorts:    mcpPorts,
		A2APorts:    a2aPorts,
		Concurrency: concurrency,
		Timeout:     timeout,
		Insecure:    insecure,
		ExpandOpts: networkscan.ExpandOptions{
			AllowLargeCIDR:     allowLarge,
			AllowPublicTargets: allowPublic,
		},
	}

	ctx := context.Background()
	_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[discover] expanding targets: %s\n", spec)
	targets, err := scanner.Scan(ctx, spec)
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("discover: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStderr(),
		"[discover] discovered %d endpoint(s)\n", len(targets))
	for _, t := range targets {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(),
			"[discover]   %s — protocol=%s url=%s\n",
			t.Address, t.Meta["protocol"], t.Meta["url"])
	}

	envelope := buildDiscoverEnvelope(spec, targets, authzFile, authzHash, allowPublic)
	if output == "" {
		output = fmt.Sprintf("discover-%s.json", envelope.Meta.ScanID)
	}
	if output == "-" {
		return writeCollectorOutputStdout(envelope)
	}
	return writeCollectorOutput(envelope, output)
}

func buildDiscoverEnvelope(spec string, targets []action.Target, authzFile, authzHash string, allowPublic bool) *ingest.IngestData {
	scanID := uuid.New().String()
	env := &ingest.IngestData{
		Meta: ingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        "scan",
			CollectorVersion: "0.3.0-dev",
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			ScanID:           scanID,
			Extra: map[string]any{
				"discover_spec":        spec,
				"discover_targets":     len(targets),
				"allow_public_targets": allowPublic,
			},
		},
	}
	if authzFile != "" {
		env.Meta.Extra["authorization_file_path"] = authzFile
		env.Meta.Extra["authorization_file_sha256"] = authzHash
	}
	env.Graph = protoscan.EmitDiscoveryNodes(targets)
	return env
}

package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/modules/protoscan"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/spf13/cobra"
)

const discoverInitializeOK = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"discover-test","version":"1.0.0"},"capabilities":{}}}`

// joinPorts renders a port slice in the "/"-separated form used in the
// discover long-help prose (e.g. {3000,8000} -> "3000/8000").
func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, "/")
}

// TestDiscoverLongHelpMatchesDefaultPorts guards the discover long-help
// prose against drift from the actual default probe port sets. Before the
// fix the prose listed only "3000/8080/8443" for MCP and "80/443" for A2A,
// omitting 8000 (MCP) and 3000/8080 (A2A) that protoscan.DefaultMCPPorts /
// DefaultA2APorts actually probe. Deriving the expected strings from the
// constants keeps this test correct if the defaults ever change.
func TestDiscoverLongHelpMatchesDefaultPorts(t *testing.T) {
	mcp := joinPorts(protoscan.DefaultMCPPorts)
	a2a := joinPorts(protoscan.DefaultA2APorts)

	if !strings.Contains(discoverCmd.Long, mcp) {
		t.Errorf("discover long help missing MCP default ports %q\nLong:\n%s", mcp, discoverCmd.Long)
	}
	if !strings.Contains(discoverCmd.Long, a2a) {
		t.Errorf("discover long help missing A2A default ports %q\nLong:\n%s", a2a, discoverCmd.Long)
	}
}

func TestBuildDiscoverEnvelopeUsesProbeCoverage(t *testing.T) {
	for _, tt := range []struct {
		name   string
		report protoscan.ProbeReport
		want   ingest.OutcomeState
	}{
		{
			name:   "all conclusive",
			report: protoscan.ProbeReport{Total: 4, Conclusive: 4},
			want:   ingest.OutcomeComplete,
		},
		{
			name:   "mixed",
			report: protoscan.ProbeReport{Total: 4, Conclusive: 2},
			want:   ingest.OutcomePartial,
		},
		{
			name:   "nothing conclusive",
			report: protoscan.ProbeReport{Total: 4},
			want:   ingest.OutcomeFailed,
		},
		{
			name:   "zero probes",
			report: protoscan.ProbeReport{},
			want:   ingest.OutcomeFailed,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			contract := buildProtocolProbeContract(tt.report)
			identity, err := identifyProbeContract("discover", contract)
			if err != nil {
				t.Fatalf("identify probe contract: %v", err)
			}
			envelope := buildDiscoverEnvelope(
				"127.0.0.1",
				nil,
				"",
				"",
				false,
				tt.report,
				identity,
				contract,
			)
			if envelope.Meta.Collection.State != tt.want {
				t.Fatalf("collection state = %q, want %q",
					envelope.Meta.Collection.State, tt.want)
			}
			outcome := envelope.Meta.Collection.Outcomes[0]
			if outcome.State != tt.want {
				t.Fatalf("protocol outcome = %+v, want %q", outcome, tt.want)
			}
			if tt.want != ingest.OutcomeComplete && outcome.Error == "" {
				t.Fatalf("incomplete protocol outcome lacks diagnostic: %+v", outcome)
			}
		})
	}
}

func TestRunDiscoverPrintsOneCoverageAwareIngestInstruction(t *testing.T) {
	positive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(discoverInitializeOK))
	}))
	defer positive.Close()
	concealed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer concealed.Close()

	positivePort := discoverTestPort(t, positive.URL)
	concealedPort := discoverTestPort(t, concealed.URL)
	for _, tt := range []struct {
		name          string
		ports         []int
		wantWarning   string
		wantQualified bool
	}{
		{
			name:  "complete",
			ports: []int{positivePort},
		},
		{
			name:          "partial",
			ports:         []int{positivePort, concealedPort},
			wantWarning:   "WARNING: Scan artifact is partial",
			wantQualified: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "discover.json")
			var output bytes.Buffer
			cmd := discoverGuidanceTestCommand(outputPath, tt.ports)
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			var runErr error
			processStderr := captureDiscoverProcessStderr(t, func() {
				runErr = runDiscover(cmd, []string{"127.0.0.1"})
			})
			if runErr != nil {
				t.Fatalf("runDiscover: %v", runErr)
			}
			text := processStderr + output.String()
			if count := strings.Count(text, "agenthound-server ingest "); count != 1 {
				t.Fatalf("ingest instruction count = %d, want 1:\n%s", count, text)
			}
			plain := "Next: agenthound-server ingest " + outputPath
			qualified := "Next (after reviewing incomplete coverage): agenthound-server ingest " + outputPath
			if tt.wantQualified {
				if strings.Contains(text, plain) {
					t.Fatalf("partial output contains unqualified instruction:\n%s", text)
				}
				if !strings.Contains(text, qualified) {
					t.Fatalf("partial output lacks qualified instruction:\n%s", text)
				}
			} else {
				if !strings.Contains(text, plain) || strings.Contains(text, "Next (") {
					t.Fatalf("complete output does not contain one plain instruction:\n%s", text)
				}
			}
			if tt.wantWarning != "" && !strings.Contains(text, tt.wantWarning) {
				t.Fatalf("output lacks warning %q:\n%s", tt.wantWarning, text)
			}
		})
	}
}

func captureDiscoverProcessStderr(t *testing.T, run func()) string {
	t.Helper()
	previous := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr capture pipe: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = previous
		_ = writer.Close()
		_ = reader.Close()
	}()

	run()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr capture: %v", err)
	}
	os.Stderr = previous
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr capture: %v", err)
	}
	return string(output)
}

func discoverGuidanceTestCommand(output string, ports []int) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.PersistentFlags().Bool("quiet", true, "")
	cmd.Flags().Bool("mcp", true, "")
	cmd.Flags().Bool("a2a", false, "")
	cmd.Flags().IntSlice("mcp-ports", ports, "")
	cmd.Flags().IntSlice("a2a-ports", nil, "")
	cmd.Flags().Int("network-scan-concurrency", 2, "")
	cmd.Flags().Duration("timeout", time.Second, "")
	cmd.Flags().Bool("insecure", false, "")
	cmd.Flags().Bool("allow-public-targets", false, "")
	cmd.Flags().Bool("allow-large-cidr", false, "")
	cmd.Flags().String("authorization-file", "", "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().String("scan-output", output, "")
	return cmd
}

func discoverTestPort(t *testing.T, rawURL string) int {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}
	return port
}

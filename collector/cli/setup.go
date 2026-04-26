package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/adithyan-ak/agenthound/collector/apiclient"
	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Save the AgentHound server URL to the per-user client config",
	Long: `Configure the collector to ship JSON to an AgentHound server.

This writes the chosen --server URL to ~/.config/agenthound/config.yaml so
subsequent 'agenthound scan' invocations can find it.

Auth has been removed; there is no login step.`,
	RunE: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

func runSetup(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	serverURL := resolveServerURL(cmd)
	if serverURL == "" {
		serverURL = promptInput("Server URL", "http://localhost:8080")
	}

	client := apiclient.New(serverURL)
	if err := client.Health(ctx); err != nil {
		return fmt.Errorf("cannot reach server at %s: %w\nMake sure agenthound-server is running", serverURL, err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "Server reachable at %s\n", serverURL)

	if err := clientcfg.SaveClientConfig(&clientcfg.ClientConfig{ServerURL: serverURL}); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stderr, "\nSetup complete. Config saved to %s\n", clientcfg.ClientConfigPath())
	_, _ = fmt.Fprintf(os.Stderr, "Server: %s\n\n", serverURL)
	_, _ = fmt.Fprintf(os.Stderr, "Run 'agenthound scan' to scan your infrastructure.\n")
	return nil
}

func resolveServerURL(cmd *cobra.Command) string {
	if v, _ := cmd.Root().PersistentFlags().GetString("server-url"); v != "" {
		return v
	}
	if v := os.Getenv("AGENTHOUND_SERVER_URL"); v != "" {
		return v
	}
	return ""
}

func promptInput(label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultVal)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		val := strings.TrimSpace(scanner.Text())
		if val != "" {
			return val
		}
	}
	return defaultVal
}

package cli

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveServerURL_DefaultEmpty(t *testing.T) {
	t.Setenv("AGENTHOUND_SERVER_URL", "")
	cmd := &cobra.Command{}
	cmd.PersistentFlags().String("server-url", "", "")
	root := &cobra.Command{}
	root.PersistentFlags().String("server-url", "", "")
	root.AddCommand(cmd)

	got := resolveServerURL(cmd)
	if got != "" {
		t.Errorf("resolveServerURL() = %q, want empty (caller prompts for default)", got)
	}
}

func TestResolveServerURL_Env(t *testing.T) {
	t.Setenv("AGENTHOUND_SERVER_URL", "http://myhost:9090")
	cmd := &cobra.Command{}
	root := &cobra.Command{}
	root.PersistentFlags().String("server-url", "", "")
	root.AddCommand(cmd)

	got := resolveServerURL(cmd)
	if got != "http://myhost:9090" {
		t.Errorf("resolveServerURL() = %q, want %q", got, "http://myhost:9090")
	}
}

func TestResolveServerURL_Flag(t *testing.T) {
	t.Setenv("AGENTHOUND_SERVER_URL", "http://env-url:9090")
	cmd := &cobra.Command{}
	root := &cobra.Command{}
	root.PersistentFlags().String("server-url", "", "")
	root.AddCommand(cmd)
	_ = root.PersistentFlags().Set("server-url", "http://flag-url:7070")

	got := resolveServerURL(cmd)
	if got != "http://flag-url:7070" {
		t.Errorf("resolveServerURL() = %q, want %q", got, "http://flag-url:7070")
	}
}

func TestPromptInput_Default(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString("\n")
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	got := promptInput("Server URL", "http://localhost:8080")
	if got != "http://localhost:8080" {
		t.Errorf("promptInput() = %q, want %q", got, "http://localhost:8080")
	}
}

func TestPromptInput_Custom(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString("http://custom:9090\n")
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	got := promptInput("Server URL", "http://localhost:8080")
	if got != "http://custom:9090" {
		t.Errorf("promptInput() = %q, want %q", got, "http://custom:9090")
	}
}

func TestPromptInput_EmptyDefault(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString("\n")
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	got := promptInput("Server URL", "")
	if got != "" {
		t.Errorf("promptInput() = %q, want %q", got, "")
	}
}

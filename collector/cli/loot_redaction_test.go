package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestRunLoot_CredentialSpecRedacted is a hard regression guard on
// U-HIGH-6: the operator's raw --credential value MUST NEVER appear
// verbatim in an error returned from runLoot.
//
// Repro of the pre-fix leak: `--credential sk-SECRET-...` (no `=`)
// caused runLoot to return `fmt.Errorf("invalid --credential %q:
// expected KEY=VALUE", spec)`. Cobra prints that error to stderr and
// main.go prints it again — the raw sk-SECRET-... string appeared
// twice in the operator's terminal (and any log capture pointed at
// stderr, e.g. SIEM ingestion).
//
// The fix routes spec through sdk/common.Redact so the returned error
// carries only the 8-char prefix.
func TestRunLoot_CredentialSpecRedacted(t *testing.T) {
	const secret = "sk-SECRET-LEAK-TEST-do-not-log"

	cmd := &cobra.Command{Use: "loot", RunE: runLoot}
	// Mirror the flag set that init() attaches on the real lootCmd —
	// the pieces exercised by our error path.
	cmd.Flags().String("type", "", "")
	cmd.Flags().String("master-key", "", "")
	cmd.Flags().StringSlice("credential", nil, "")
	cmd.Flags().Bool("include-credential-values", false, "")
	cmd.Flags().Int("max-items", 0, "")
	cmd.Flags().String("engagement-id", "", "")
	cmd.Flags().Duration("timeout", 0, "")

	// The bare `--credential <secret>` (no `=`) hits the redaction
	// branch. We also supply --type so we get past the required-flag
	// gate before the credential parse.
	cmd.SetArgs([]string{
		"127.0.0.1:4000",
		"--type", "litellm",
		"--credential", secret,
	})
	var stderr bytes.Buffer
	cmd.SetOut(&stderr)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error on bare --credential; got nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("raw --credential value leaked into error message:\n  err = %q\n  secret = %q", err.Error(), secret)
	}
	// Sanity: the 8-char prefix from common.Redact should appear.
	wantPrefix := secret[:8] + "..."
	if !strings.Contains(err.Error(), wantPrefix) {
		t.Errorf("expected redacted prefix %q in error; got %q", wantPrefix, err.Error())
	}
	// Belt-and-braces: check stderr too — if a future refactor prints
	// the raw value via cmd.PrintErr somewhere earlier in the parse
	// chain, this catches it.
	if strings.Contains(stderr.String(), secret) {
		t.Errorf("raw --credential value leaked to stderr:\n%s", stderr.String())
	}
}

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

// setupSentinels creates all sentinel files in a temp dir and sets HOME
// so the AUTHORIZED prompts are bypassed. Also resets rootCmd args.
func setupSentinels(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	ahDir := filepath.Join(home, ".agenthound")
	_ = os.MkdirAll(ahDir, 0o700)
	for _, name := range []string{"loot-acknowledged", "poison-acknowledged", "extract-acknowledged"} {
		_ = os.WriteFile(filepath.Join(ahDir, name), []byte(`{}`), 0o600)
	}
	// Reset rootCmd state between tests to avoid arg pollution.
	rootCmd.SetArgs(nil)
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	return home
}

// --- Mock Looter ---

type mockLooter struct {
	called  bool
	result  *action.LootResult
	err     error
	gotOpts action.LootOptions
}

func (m *mockLooter) ID() string            { return "mock.loot" }
func (m *mockLooter) Action() action.Action { return action.Loot }
func (m *mockLooter) Target() string        { return "mock-svc" }
func (m *mockLooter) Description() string   { return "mock" }
func (m *mockLooter) Version() string       { return "0.0.0" }
func (m *mockLooter) IsDestructive() bool   { return false }
func (m *mockLooter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	m.called = true
	m.gotOpts = opts
	if m.err != nil {
		return nil, m.err
	}
	if m.result != nil {
		return m.result, nil
	}
	return &action.LootResult{
		IngestData: &ingest.IngestData{},
		Summary:    action.LootSummary{CredentialsFound: 3},
	}, nil
}

// --- Mock Extractor ---

type mockExtractor struct {
	called bool
}

func (m *mockExtractor) ID() string            { return "mock.extract" }
func (m *mockExtractor) Action() action.Action { return action.Extract }
func (m *mockExtractor) Target() string        { return "mock-extract" }
func (m *mockExtractor) Description() string   { return "mock" }
func (m *mockExtractor) Version() string       { return "0.0.0" }
func (m *mockExtractor) IsDestructive() bool   { return false }
func (m *mockExtractor) Extract(ctx context.Context, t action.Target, opts action.ExtractOptions) (*action.ExtractResult, error) {
	m.called = true
	if opts.DryRun {
		return &action.ExtractResult{
			Summary: action.ExtractSummary{ArtifactsProduced: 5, DryRun: true},
		}, nil
	}
	return &action.ExtractResult{
		IngestData: &ingest.IngestData{
			Graph: ingest.GraphData{
				Nodes: []ingest.Node{{ID: "sha256:test", Kinds: []string{"ExtractedTrainingSignal"}}},
			},
		},
		Summary: action.ExtractSummary{ArtifactsProduced: 5},
	}, nil
}

// --- Mock Poisoner/Reverter ---

type mockPoisoner struct {
	id         string
	targetKind string
	state      *module.FileStatefulModule

	called    bool
	target    action.Target
	payload   action.PoisonPayload
	err       error
	revertErr error

	revertCalls int
	authToken   string
}

func newMockPoisoner(id, targetKind string) *mockPoisoner {
	return &mockPoisoner{
		id:         id,
		targetKind: targetKind,
		state:      module.NewFileStatefulModule(id),
	}
}

func (m *mockPoisoner) ID() string            { return m.id }
func (m *mockPoisoner) Action() action.Action { return action.Poison }
func (m *mockPoisoner) Target() string        { return m.targetKind }
func (m *mockPoisoner) Description() string   { return "mock poisoner" }
func (m *mockPoisoner) Version() string       { return "0.0.0" }
func (m *mockPoisoner) IsDestructive() bool   { return true }
func (m *mockPoisoner) Stateful() module.StatefulModule {
	return m.state
}
func (m *mockPoisoner) Poison(ctx context.Context, t action.Target, payload action.PoisonPayload) (*action.PoisonReceipt, error) {
	m.called = true
	m.target = t
	m.payload = payload
	if m.err != nil {
		return nil, m.err
	}
	return &action.PoisonReceipt{
		ModuleID:        m.id,
		EngagementID:    payload.EngagementID,
		Target:          t,
		TargetID:        payload.TargetID,
		OriginalContent: "original",
		InjectedContent: payload.InjectionContent,
		Mode:            payload.Mode,
		DryRun:          payload.DryRun,
	}, nil
}
func (m *mockPoisoner) Revert(ctx context.Context, receipt action.Receipt) error {
	m.revertCalls++
	if token, ok := ctx.Value(action.RevertAuthTokenKey{}).(string); ok {
		m.authToken = token
	}
	return m.revertErr
}

func newPoisonTestCmd(input string, out *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "poison"}
	cmd.Flags().String("type", "", "")
	cmd.Flags().String("target-id", "", "")
	cmd.Flags().String("inject", "", "")
	cmd.Flags().String("inject-file", "", "")
	cmd.Flags().String("mode", "replace", "")
	cmd.Flags().Bool("commit", false, "")
	cmd.Flags().String("engagement-id", "", "")
	cmd.SetIn(strings.NewReader(input))
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd
}

func newRevertTestCmd(out *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "revert"}
	cmd.Flags().String("auth-token", "", "")
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd
}

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set flag %s: %v", name, err)
	}
}

// --- Loot tests ---

func TestRunLoot_HappyPath(t *testing.T) {
	setupSentinels(t)
	mock := &mockLooter{}
	module.Register(mock)
	defer deregisterModule(t, "mock.loot")

	out := &bytes.Buffer{}
	lootCmd.SetOut(out)
	lootCmd.SetErr(out)
	_ = lootCmd.Flags().Set("type", "mock-svc")
	_ = lootCmd.Flags().Set("engagement-id", "TEST")
	// Use root --output to stdout so writeCollectorOutput goes to buffer.
	_ = rootCmd.PersistentFlags().Set("output", "-")
	defer func() { _ = rootCmd.PersistentFlags().Set("output", "") }()
	err := runLoot(lootCmd, []string{"10.0.0.1:4000"})
	if err != nil {
		t.Fatalf("runLoot: %v", err)
	}
	if !mock.called {
		t.Error("mock Looter was not called")
	}
	if !strings.Contains(out.String(), "credentials_found=3") {
		t.Errorf("output missing credential count: %s", out.String())
	}
}

func TestRunLoot_NoModule(t *testing.T) {
	setupSentinels(t)
	out := &bytes.Buffer{}
	lootCmd.SetOut(out)
	lootCmd.SetErr(out)
	_ = lootCmd.Flags().Set("type", "definitely-not-registered")
	_ = lootCmd.Flags().Set("engagement-id", "X")
	err := runLoot(lootCmd, []string{"10.0.0.1:4000"})
	if err == nil || !strings.Contains(err.Error(), "no looter registered") {
		t.Errorf("expected 'no looter registered' error, got: %v", err)
	}
}

// timeoutMockLooter is a Looter with a distinct registry ID/target so it can
// coexist with mockLooter ("mock.loot"/"mock-svc") in the same test binary
// without a duplicate-registration panic.
type timeoutMockLooter struct {
	gotTimeout time.Duration
}

func (m *timeoutMockLooter) ID() string            { return "mock.loot.timeout" }
func (m *timeoutMockLooter) Action() action.Action { return action.Loot }
func (m *timeoutMockLooter) Target() string        { return "mock-timeout-svc" }
func (m *timeoutMockLooter) Description() string   { return "mock" }
func (m *timeoutMockLooter) Version() string       { return "0.0.0" }
func (m *timeoutMockLooter) IsDestructive() bool   { return false }
func (m *timeoutMockLooter) Loot(ctx context.Context, t action.Target, opts action.LootOptions) (*action.LootResult, error) {
	m.gotTimeout = opts.Timeout
	return &action.LootResult{IngestData: &ingest.IngestData{}}, nil
}

// TestRunLoot_TimeoutFlowsThrough is the Finding 11 regression: loot's init()
// now registers --timeout, so a non-zero value reaches LootOptions.Timeout.
// Before the fix the flag was read but never registered, so GetDuration
// swallowed the lookup error and the looter always saw the zero default.
func TestRunLoot_TimeoutFlowsThrough(t *testing.T) {
	setupSentinels(t)
	mock := &timeoutMockLooter{}
	module.Register(mock)
	defer deregisterModule(t, mock.ID())

	out := &bytes.Buffer{}
	lootCmd.SetOut(out)
	lootCmd.SetErr(out)
	mustSetFlag(t, lootCmd, "type", mock.Target())
	mustSetFlag(t, lootCmd, "engagement-id", "TEST")
	mustSetFlag(t, lootCmd, "timeout", "42s")
	_ = rootCmd.PersistentFlags().Set("output", "-")
	defer func() { _ = rootCmd.PersistentFlags().Set("output", "") }()

	captureStdout(t, func() {
		if err := runLoot(lootCmd, []string{"10.0.0.1:4000"}); err != nil {
			t.Fatalf("runLoot: %v", err)
		}
	})

	if mock.gotTimeout != 42*time.Second {
		t.Errorf("looter received timeout %v, want 42s", mock.gotTimeout)
	}
}

// --- Poison/Revert tests ---

func TestRunPoison_DryRunPromptsAndPersistsReceipt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))

	mock := newMockPoisoner("mock.poison.dryrun", "mock-poison-dryrun")
	module.Register(mock)
	defer deregisterModule(t, mock.ID())

	out := &bytes.Buffer{}
	cmd := newPoisonTestCmd("AUTHORIZED\n", out)
	mustSetFlag(t, cmd, "type", mock.Target())
	mustSetFlag(t, cmd, "target-id", "tool-1")
	mustSetFlag(t, cmd, "inject", "replace me")
	mustSetFlag(t, cmd, "mode", "append")
	mustSetFlag(t, cmd, "engagement-id", "ENG-CLI-POISON")

	if err := runPoison(cmd, []string{"127.0.0.1:8080"}); err != nil {
		t.Fatalf("runPoison: %v", err)
	}
	if !mock.called {
		t.Fatal("mock Poisoner was not called")
	}
	if mock.target.Address != "127.0.0.1:8080" {
		t.Errorf("target address = %q, want 127.0.0.1:8080", mock.target.Address)
	}
	if !mock.payload.DryRun {
		t.Error("expected dry-run payload when --commit is unset")
	}
	if mock.payload.TargetID != "tool-1" || mock.payload.InjectionContent != "replace me" || mock.payload.Mode != "append" {
		t.Errorf("payload not wired correctly: %+v", mock.payload)
	}
	if !strings.Contains(out.String(), "authorization confirmed") || !strings.Contains(out.String(), "DRY-RUN") {
		t.Errorf("expected authorization and DRY-RUN output, got: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".agenthound", "poison-acknowledged")); err != nil {
		t.Fatalf("poison sentinel was not written: %v", err)
	}

	receipts, err := mock.state.ReadReceipts("ENG-CLI-POISON")
	if err != nil {
		t.Fatalf("ReadReceipts: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 dry-run receipt, got %d", len(receipts))
	}
	receipt, ok := receipts[0].(*action.PoisonReceipt)
	if !ok {
		t.Fatalf("receipt type = %T, want *action.PoisonReceipt", receipts[0])
	}
	if !receipt.DryRun || receipt.TargetID != "tool-1" {
		t.Errorf("unexpected persisted receipt: %+v", receipt)
	}
}

func TestRunPoison_AuthorizationRejected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))

	out := &bytes.Buffer{}
	cmd := newPoisonTestCmd("not authorized\n", out)
	mustSetFlag(t, cmd, "type", "unused")
	mustSetFlag(t, cmd, "inject", "payload")
	mustSetFlag(t, cmd, "engagement-id", "ENG-CLI-REJECT")

	err := runPoison(cmd, []string{"127.0.0.1:8080"})
	if err == nil || !strings.Contains(err.Error(), "authorization not confirmed") {
		t.Fatalf("expected authorization rejection, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".agenthound", "poison-acknowledged")); !os.IsNotExist(statErr) {
		t.Fatalf("sentinel should not be written on rejection, stat err: %v", statErr)
	}
}

func TestRunRevert_DispatchesNonDryRunAndSkipsDryRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))

	mock := newMockPoisoner("mock.poison.revert", "mock-poison-revert")
	module.Register(mock)
	defer deregisterModule(t, mock.ID())

	if _, err := mock.state.WriteReceipt("ENG-CLI-REVERT", &action.PoisonReceipt{
		ModuleID:     mock.ID(),
		EngagementID: "ENG-CLI-REVERT",
		DryRun:       true,
	}); err != nil {
		t.Fatalf("write dry-run receipt: %v", err)
	}
	if _, err := mock.state.WriteReceipt("ENG-CLI-REVERT", &action.PoisonReceipt{
		ModuleID:     mock.ID(),
		EngagementID: "ENG-CLI-REVERT",
		TargetID:     "tool-1",
		DryRun:       false,
	}); err != nil {
		t.Fatalf("write applied receipt: %v", err)
	}

	out := &bytes.Buffer{}
	cmd := newRevertTestCmd(out)
	mustSetFlag(t, cmd, "auth-token", "test-token")

	if err := runRevert(cmd, []string{"ENG-CLI-REVERT"}); err != nil {
		t.Fatalf("runRevert: %v", err)
	}
	if mock.revertCalls != 1 {
		t.Fatalf("revert calls = %d, want 1", mock.revertCalls)
	}
	if mock.authToken != "test-token" {
		t.Errorf("auth token = %q, want test-token", mock.authToken)
	}
	if !strings.Contains(out.String(), "dry-run receipt") || !strings.Contains(out.String(), "1 reverted") {
		t.Errorf("unexpected revert output: %s", out.String())
	}
}

// --- Implant tests ---

// TestRunImplant_FallsBackToPoisoner guards the v0.5 fix where
// `agenthound implant --type instruction.file` was previously broken:
// instructionpoison registers as action.Poison but the docs surface
// instruction.file under `implant`. runImplant now falls back to a
// Poisoner lookup with the same target kind. The test exercises the
// fallback by registering only a Poisoner-shaped mock with a target
// kind that has no Implanter and confirming Poison() is invoked.
func TestRunImplant_FallsBackToPoisoner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTHOUND_STATE_DIR", filepath.Join(t.TempDir(), "state"))

	mock := newMockPoisoner("mock.poison.implantfallback", "mock-implant-fallback")
	module.Register(mock)
	defer deregisterModule(t, mock.ID())

	out := &bytes.Buffer{}
	cmd := &cobra.Command{Use: "implant"}
	cmd.Flags().String("type", "", "")
	cmd.Flags().String("target-id", "", "")
	cmd.Flags().String("inject", "", "")
	cmd.Flags().String("inject-file", "", "")
	cmd.Flags().Bool("commit", false, "")
	cmd.Flags().String("engagement-id", "", "")
	cmd.SetIn(strings.NewReader("AUTHORIZED\n"))
	cmd.SetOut(out)
	cmd.SetErr(out)

	mustSetFlag(t, cmd, "type", mock.Target())
	mustSetFlag(t, cmd, "target-id", "/tmp/CLAUDE.md")
	mustSetFlag(t, cmd, "inject", "instruction body")
	mustSetFlag(t, cmd, "engagement-id", "ENG-CLI-IMPLANT-FB")

	if err := runImplant(cmd, []string{"127.0.0.1:8080"}); err != nil {
		t.Fatalf("runImplant: %v", err)
	}
	if !mock.called {
		t.Fatal("Poisoner fallback was not invoked")
	}
	if !mock.payload.DryRun {
		t.Error("expected dry-run when --commit unset")
	}
	if mock.payload.InjectionContent != "instruction body" {
		t.Errorf("payload InjectionContent = %q, want 'instruction body'", mock.payload.InjectionContent)
	}
	if !strings.Contains(out.String(), "[implant]") {
		t.Errorf("expected [implant] label in output, got: %s", out.String())
	}
}

// TestRunImplant_NoModuleAndNoFallback confirms the original error
// surface still fires when neither an Implanter NOR a Poisoner matches
// the requested target kind.
func TestRunImplant_NoModuleAndNoFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".agenthound"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".agenthound", "poison-acknowledged"), []byte(`{}`), 0o600)

	out := &bytes.Buffer{}
	cmd := &cobra.Command{Use: "implant"}
	cmd.Flags().String("type", "", "")
	cmd.Flags().String("target-id", "", "")
	cmd.Flags().String("inject", "", "")
	cmd.Flags().String("inject-file", "", "")
	cmd.Flags().Bool("commit", false, "")
	cmd.Flags().String("engagement-id", "", "")
	cmd.SetOut(out)
	cmd.SetErr(out)

	mustSetFlag(t, cmd, "type", "definitely-not-registered-anywhere")
	mustSetFlag(t, cmd, "inject", "x")
	mustSetFlag(t, cmd, "engagement-id", "ENG-IMPLANT-MISS")

	err := runImplant(cmd, []string{"127.0.0.1:8080"})
	if err == nil || !strings.Contains(err.Error(), "no implanter registered") {
		t.Errorf("expected 'no implanter registered' error, got: %v", err)
	}
}

// --- Extract tests ---

func TestRunExtract_DryRun(t *testing.T) {
	setupSentinels(t)
	mock := &mockExtractor{}
	module.Register(mock)
	defer deregisterModule(t, "mock.extract")

	tmpArtifact := filepath.Join(t.TempDir(), "test.gguf")
	_ = os.WriteFile(tmpArtifact, []byte("fake"), 0o600)

	out := &bytes.Buffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetArgs([]string{"extract", "sha256:node-id", "--type", "mock-extract",
		"--artifact", tmpArtifact, "--engagement-id", "TEST"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !mock.called {
		t.Error("mock Extractor was not called")
	}
	if !strings.Contains(out.String(), "DRY-RUN") {
		t.Errorf("expected DRY-RUN in output: %s", out.String())
	}
}

func TestRunExtract_NoModule(t *testing.T) {
	setupSentinels(t)
	out := &bytes.Buffer{}
	extractCmd.SetOut(out)
	extractCmd.SetErr(out)
	_ = extractCmd.Flags().Set("type", "not-registered-extractor")
	_ = extractCmd.Flags().Set("engagement-id", "TEST")
	_ = extractCmd.Flags().Set("artifact", "/tmp/fake.gguf")
	err := runExtract(extractCmd, []string{"sha256:node-id"})
	if err == nil || !strings.Contains(err.Error(), "no extractor registered") {
		t.Errorf("expected 'no extractor registered' error, got: %v", err)
	}
}

// deregisterModule removes a module from the registry after test.
// This is a test-only hack — the registry doesn't expose a Remove API,
// so we reach in via the package-internal access (same package).
func deregisterModule(t *testing.T, id string) {
	t.Helper()
	// Since we're in package cli (not package module), we can't directly
	// access the registry map. Instead we just accept that re-registration
	// in the same process will panic. Tests using mocks should use
	// unique IDs or subtests with separate processes.
	// For now, this is a no-op placeholder — the mock IDs don't collide
	// with real modules because they use "mock.*" prefix.
}

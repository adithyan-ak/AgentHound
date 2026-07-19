package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

type blockingPoisoner struct {
	id             string
	targetKind     string
	state          *module.FileStatefulModule
	started        chan struct{}
	persistReceipt bool
}

func newBlockingPoisoner(id, targetKind string, persistReceipt bool) *blockingPoisoner {
	return &blockingPoisoner{
		id: id, targetKind: targetKind, state: module.NewFileStatefulModule(id),
		started: make(chan struct{}), persistReceipt: persistReceipt,
	}
}

func (p *blockingPoisoner) ID() string                                   { return p.id }
func (p *blockingPoisoner) Action() action.Action                        { return action.Poison }
func (p *blockingPoisoner) Target() string                               { return p.targetKind }
func (p *blockingPoisoner) Description() string                          { return "blocking poisoner test double" }
func (p *blockingPoisoner) Version() string                              { return "test" }
func (p *blockingPoisoner) IsDestructive() bool                          { return true }
func (p *blockingPoisoner) Stateful() module.StatefulModule              { return p.state }
func (p *blockingPoisoner) Revert(context.Context, action.Receipt) error { return nil }

func (p *blockingPoisoner) Poison(ctx context.Context, target action.Target, payload action.PoisonPayload) (*action.PoisonReceipt, error) {
	receipt := &action.PoisonReceipt{
		ReceiptID: "blocking-receipt", ModuleID: p.id, EngagementID: payload.EngagementID,
		Target: target, TargetID: payload.TargetID, OriginalContent: "original",
		InjectedContent: payload.InjectionContent, Mode: payload.Mode, DryRun: payload.DryRun,
	}
	if p.persistReceipt {
		if _, err := p.state.WriteReceipt(payload.EngagementID, receipt); err != nil {
			return nil, err
		}
	}
	close(p.started)
	<-ctx.Done()
	if p.persistReceipt {
		return receipt, fmt.Errorf("%w: %w", action.ErrRevertIndeterminate, ctx.Err())
	}
	return nil, ctx.Err()
}

func TestRunPoisonBoundsAStalledModuleBeforeReceipt(t *testing.T) {
	originalTimeout := standalonePoisonTimeout
	standalonePoisonTimeout = 50 * time.Millisecond
	t.Cleanup(func() { standalonePoisonTimeout = originalTimeout })

	p := newBlockingPoisoner("mock.poison.timeout", "mock-timeout", false)
	module.Register(p)
	defer deregisterModule(t, p.ID())
	state, _, err := executeBlockingPoison(t, context.Background(), p, "ENG-TIMEOUT")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run poison error = %v, want deadline exceeded", err)
	}
	if receipts, readErr := state.ReadReceipts("ENG-TIMEOUT"); readErr != nil || len(receipts) != 0 {
		t.Fatalf("pre-mutation timeout receipts = %d, error=%v", len(receipts), readErr)
	}
}

func TestRunPoisonPropagatesCommandCancellation(t *testing.T) {
	originalTimeout := standalonePoisonTimeout
	standalonePoisonTimeout = time.Second
	t.Cleanup(func() { standalonePoisonTimeout = originalTimeout })

	p := newBlockingPoisoner("mock.poison.cancel", "mock-cancel", false)
	module.Register(p)
	defer deregisterModule(t, p.ID())
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-p.started
		cancel()
	}()
	_, _, err := executeBlockingPoison(t, ctx, p, "ENG-CANCEL")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run poison error = %v, want canceled", err)
	}
}

func TestRunPoisonReportsAmbiguousCommittedStateAndRecoveryReceipt(t *testing.T) {
	originalTimeout := standalonePoisonTimeout
	standalonePoisonTimeout = 50 * time.Millisecond
	t.Cleanup(func() { standalonePoisonTimeout = originalTimeout })

	p := newBlockingPoisoner("mock.poison.ambiguous", "mock-ambiguous", true)
	module.Register(p)
	defer deregisterModule(t, p.ID())
	state, output, err := executeBlockingPoison(t, context.Background(), p, "ENG-AMBIGUOUS")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run poison error = %v, want deadline exceeded", err)
	}
	if !strings.Contains(output, "INDETERMINATE") ||
		!strings.Contains(output, "agenthound revert ENG-AMBIGUOUS") {
		t.Fatalf("missing recovery diagnostics: %s", output)
	}
	receipts, readErr := state.ReadReceipts("ENG-AMBIGUOUS")
	if readErr != nil || len(receipts) != 1 {
		t.Fatalf("recovery receipts = %d, error=%v", len(receipts), readErr)
	}
}

func TestRunPoisonRecoveryHintPreservesExplicitInsecureFlag(t *testing.T) {
	originalTimeout := standalonePoisonTimeout
	standalonePoisonTimeout = 50 * time.Millisecond
	t.Cleanup(func() { standalonePoisonTimeout = originalTimeout })

	p := newBlockingPoisoner("mock.poison.ambiguous.insecure", "mock-ambiguous-insecure", true)
	module.Register(p)
	defer deregisterModule(t, p.ID())
	setupSentinels(t)
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())
	p.state = module.NewFileStatefulModule(p.id)
	out := &bytes.Buffer{}
	cmd := newPoisonTestCmd("", out)
	mustSetFlag(t, cmd, "type", p.targetKind)
	mustSetFlag(t, cmd, "target-id", "target")
	mustSetFlag(t, cmd, "inject", "injected")
	mustSetFlag(t, cmd, "engagement-id", "ENG-AMBIGUOUS-INSECURE")
	mustSetFlag(t, cmd, "commit", "true")
	mustSetFlag(t, cmd, "insecure", "true")
	err := runPoison(cmd, []string{"example.invalid"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run poison error = %v, want deadline exceeded", err)
	}
	if !strings.Contains(out.String(), "agenthound revert ENG-AMBIGUOUS-INSECURE --insecure") {
		t.Fatalf("recovery hint dropped explicit --insecure: %s", out.String())
	}
}

func TestRevertHintIncludesInsecureOnlyWhenExplicit(t *testing.T) {
	cmd := newPoisonTestCmd("", &bytes.Buffer{})
	if got := poisonRevertCommand(cmd, "ENG-STRICT"); got != "agenthound revert ENG-STRICT" {
		t.Fatalf("strict revert hint = %q", got)
	}
	mustSetFlag(t, cmd, "insecure", "true")
	if got := poisonRevertCommand(cmd, "ENG-INSECURE"); got != "agenthound revert ENG-INSECURE --insecure" {
		t.Fatalf("insecure revert hint = %q", got)
	}
}

func TestMutationMayRemainRejectsKnownCleanFailure(t *testing.T) {
	if mutationMayRemain(errors.New("automatic cleanup restored the original")) {
		t.Fatal("known-clean failure was classified as an ambiguous committed mutation")
	}
	for _, err := range []error{action.ErrRevertIndeterminate, context.Canceled, context.DeadlineExceeded} {
		if !mutationMayRemain(err) {
			t.Fatalf("ambiguous error %v was not classified for recovery diagnostics", err)
		}
	}
}

func executeBlockingPoison(
	t *testing.T,
	ctx context.Context,
	p *blockingPoisoner,
	engagementID string,
) (module.StatefulModule, string, error) {
	t.Helper()
	setupSentinels(t)
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())
	p.state = module.NewFileStatefulModule(p.id)
	out := &bytes.Buffer{}
	cmd := newPoisonTestCmd("", out)
	cmd.SetContext(ctx)
	mustSetFlag(t, cmd, "type", p.targetKind)
	mustSetFlag(t, cmd, "target-id", "target")
	mustSetFlag(t, cmd, "inject", "injected")
	mustSetFlag(t, cmd, "engagement-id", engagementID)
	mustSetFlag(t, cmd, "commit", "true")
	err := runPoison(cmd, []string{"example.invalid"})
	return p.state, out.String(), err
}

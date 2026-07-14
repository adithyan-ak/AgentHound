package campaign

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

const (
	RunReportVersion = 1
	maxReportSteps   = 8
)

var (
	ErrRequestBudget  = errors.New("campaign outbound request budget exhausted")
	ErrMutationBudget = errors.New("campaign mutation budget exhausted")
	ErrElapsedBudget  = errors.New("campaign elapsed-time budget exhausted")
	ErrUnsafeCleanup  = errors.New("campaign cleanup was not confirmed safe")
	ErrMutationFailed = errors.New("campaign mutation failed")
)

// RunLimits are fixed scenario-local safety bounds. Requests count outbound
// HTTP RoundTrip dispatches (including redirect/retry dispatches), mutations
// count target-changing mutator/reverter invocations, and elapsed time bounds
// forward execution. Cleanup has a separate bounded non-cancellable context.
type RunLimits struct {
	RequestLimit  int           `json:"request_limit"`
	MutationLimit int           `json:"mutation_limit"`
	ElapsedLimit  time.Duration `json:"-"`
}

// BudgetReport is the bounded wire representation of configured limits and
// actual usage.
type BudgetReport struct {
	RequestLimit   int   `json:"request_limit"`
	RequestsUsed   int   `json:"requests_used"`
	MutationLimit  int   `json:"mutation_limit"`
	MutationsUsed  int   `json:"mutations_used"`
	ElapsedLimitMS int64 `json:"elapsed_limit_ms"`
	ElapsedUsedMS  int64 `json:"elapsed_used_ms"`
}

type StepName string

const (
	StepValidateBind       StepName = "validate_bind"
	StepControlProbe       StepName = "control_probe"
	StepAuthenticatedProbe StepName = "authenticated_probe"
	StepClassify           StepName = "classify"
	StepEmit               StepName = "emit"
	StepAuthorizeMutation  StepName = "authorize_mutation"
	StepMutate             StepName = "mutate"
	StepVerifyInjected     StepName = "verify_injected"
	StepRevert             StepName = "revert"
	StepVerifyOriginal     StepName = "verify_original"
)

// StepObservation is intentionally code-only and bounded; target errors and
// request/response payloads never enter a report.
type StepObservation struct {
	Sequence    int      `json:"sequence"`
	Step        StepName `json:"step"`
	Observation string   `json:"observation"`
}

type OracleReport struct {
	Type        string `json:"type"`
	Observation string `json:"observation"`
	Outcome     string `json:"outcome"`
}

type CleanupReport struct {
	Status          RoundtripCleanup `json:"status"`
	Postcondition   string           `json:"postcondition"`
	ReceiptRetained bool             `json:"receipt_retained"`
}

type CleanupExecution struct {
	Status           RoundtripCleanup
	ReceiptsSelected int
	ReceiptsRetained bool
	FailureCode      string
}

type RunCleanupFunc func(
	ctx context.Context,
	engagementID string,
	campaignRunID string,
) CleanupExecution

// RunReport is the shared, versioned, bounded report envelope used by both
// fixed campaign scenarios. It cannot carry arbitrary metadata or target error
// text and never contains request/response payloads, credentials, or mutation
// state.
type RunReport struct {
	ReportVersion   int    `json:"report_version"`
	ScenarioID      string `json:"scenario_id"`
	ScenarioVersion int    `json:"scenario_version"`
	CampaignRunID   string `json:"campaign_run_id"`
	EngagementID    string `json:"engagement_id"`
	Standalone      bool   `json:"standalone"`

	AgentID          string `json:"agent_id,omitempty"`
	ServerID         string `json:"server_id,omitempty"`
	CredentialID     string `json:"credential_id,omitempty"`
	ResourceID       string `json:"resource_id,omitempty"`
	MutationTargetID string `json:"mutation_target_id,omitempty"`
	TargetRef        string `json:"target_ref"`

	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`

	Steps   []StepObservation `json:"steps"`
	Budget  BudgetReport      `json:"budget"`
	Oracle  OracleReport      `json:"oracle"`
	Cleanup CleanupReport     `json:"cleanup"`
}

func (r *RunReport) AddStep(step StepName, observation string) {
	if r == nil || len(r.Steps) >= maxReportSteps {
		return
	}
	r.Steps = append(r.Steps, StepObservation{
		Sequence: len(r.Steps) + 1, Step: step, Observation: observation,
	})
}

func (r RunReport) TargetClean() bool {
	return r.Cleanup.Status == CleanupRestored ||
		r.Cleanup.Status == CleanupNotApplicable
}

func (r RunReport) Summary() string {
	return "oracle=" + r.Oracle.Outcome + " cleanup=" + string(r.Cleanup.Status)
}

type budgetContextKey struct{}
type cleanupContextKey struct{}

// Budget tracks forward-run dispatches and mutations. FreezeForward captures
// the forward elapsed/exhaustion boundary before cleanup. Cleanup contexts keep
// the tracker only to identify themselves; their work is separately bounded and
// cannot consume or alter the frozen forward budget.
type Budget struct {
	mu               sync.Mutex
	limits           RunLimits
	startedAt        time.Time
	requests         int
	mutations        int
	exhausted        error
	frozen           bool
	frozenElapsed    time.Duration
	frozenExhaustion error
}

func NewBudgetContext(parent context.Context, limits RunLimits) (context.Context, context.CancelFunc, *Budget) {
	if limits.ElapsedLimit <= 0 {
		limits.ElapsedLimit = 30 * time.Second
	}
	budget := &Budget{limits: limits, startedAt: time.Now()}
	ctx := context.WithValue(parent, budgetContextKey{}, budget)
	ctx, cancel := context.WithTimeout(ctx, limits.ElapsedLimit)
	return ctx, cancel, budget
}

func (b *Budget) CleanupContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	ctx := context.WithValue(context.Background(), budgetContextKey{}, b)
	ctx = context.WithValue(ctx, cleanupContextKey{}, true)
	return context.WithTimeout(ctx, timeout)
}

func (b *Budget) Snapshot() BudgetReport {
	if b == nil {
		return BudgetReport{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked()
}

// FreezeForward atomically captures forward usage and exhaustion before cleanup
// starts. Repeated calls return the original frozen values.
func (b *Budget) FreezeForward(ctx context.Context) (BudgetReport, error) {
	if b == nil {
		return BudgetReport{}, nil
	}
	contextErr := elapsedBudgetError(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.frozen {
		b.frozen = true
		b.frozenElapsed = time.Since(b.startedAt)
		if b.frozenElapsed < 0 {
			b.frozenElapsed = 0
		}
		b.frozenExhaustion = contextErr
		if b.frozenExhaustion == nil {
			b.frozenExhaustion = b.exhausted
		}
	}
	return b.snapshotLocked(), b.frozenExhaustion
}

func (b *Budget) snapshotLocked() BudgetReport {
	elapsed := b.frozenElapsed
	if !b.frozen {
		elapsed = time.Since(b.startedAt)
	}
	if elapsed < 0 {
		elapsed = 0
	}
	return BudgetReport{
		RequestLimit:   b.limits.RequestLimit,
		RequestsUsed:   b.requests,
		MutationLimit:  b.limits.MutationLimit,
		MutationsUsed:  b.mutations,
		ElapsedLimitMS: b.limits.ElapsedLimit.Milliseconds(),
		ElapsedUsedMS:  elapsed.Milliseconds(),
	}
}

func (b *Budget) Exhaustion(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.frozen {
		err := b.frozenExhaustion
		b.mu.Unlock()
		return err
	}
	b.mu.Unlock()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrElapsedBudget
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exhausted
}

func ConsumeMutation(ctx context.Context) error {
	budget, _ := ctx.Value(budgetContextKey{}).(*Budget)
	if budget == nil {
		return nil
	}
	cleanup, _ := ctx.Value(cleanupContextKey{}).(bool)
	if cleanup {
		return ctx.Err()
	}
	if err := elapsedBudgetError(ctx); err != nil {
		return err
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.frozen {
		return context.Canceled
	}
	if budget.mutations >= budget.limits.MutationLimit {
		budget.exhausted = ErrMutationBudget
		return ErrMutationBudget
	}
	budget.mutations++
	return nil
}

// CountingTransport counts and enforces each outbound RoundTrip before
// dispatch. Wrapping an HTTP client at this layer counts redirect and caller
// retry dispatches instead of counting high-level probe operations.
type CountingTransport struct {
	Base http.RoundTripper
}

func (t CountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := consumeRequest(req.Context()); err != nil {
		return nil, err
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func consumeRequest(ctx context.Context) error {
	budget, _ := ctx.Value(budgetContextKey{}).(*Budget)
	if budget == nil {
		return nil
	}
	cleanup, _ := ctx.Value(cleanupContextKey{}).(bool)
	if cleanup {
		return ctx.Err()
	}
	if err := elapsedBudgetError(ctx); err != nil {
		return err
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.frozen {
		return context.Canceled
	}
	if budget.requests >= budget.limits.RequestLimit {
		budget.exhausted = ErrRequestBudget
		return ErrRequestBudget
	}
	budget.requests++
	return nil
}

func elapsedBudgetError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrElapsedBudget
	}
	return ctx.Err()
}

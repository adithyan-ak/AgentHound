package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCountingTransportCountsRedirectRoundTrips(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirect.Close()

	ctx, cancel, budget := NewBudgetContext(context.Background(), RunLimits{
		RequestLimit: 4, MutationLimit: 0, ElapsedLimit: time.Second,
	})
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, redirect.URL, nil)
	client := &http.Client{Transport: CountingTransport{}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := budget.Snapshot().RequestsUsed; got != 2 {
		t.Fatalf("redirect requests_used = %d, want 2", got)
	}
}

type retryingTransport struct {
	attempt http.RoundTripper
}

func (t retryingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, err := t.attempt.RoundTrip(req); err == nil {
		return nil, errors.New("first attempt unexpectedly succeeded")
	}
	return t.attempt.RoundTrip(req)
}

type failOnceTransport struct {
	calls atomic.Int32
}

func (t *failOnceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.calls.Add(1) == 1 {
		return nil, errors.New("retryable protocol failure")
	}
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestCountingTransportCountsProtocolRetryDispatches(t *testing.T) {
	ctx, cancel, budget := NewBudgetContext(context.Background(), RunLimits{
		RequestLimit: 3, MutationLimit: 0, ElapsedLimit: time.Second,
	})
	defer cancel()
	base := &failOnceTransport{}
	client := &http.Client{Transport: retryingTransport{
		attempt: CountingTransport{Base: base},
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.invalid", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := budget.Snapshot().RequestsUsed; got != 2 {
		t.Fatalf("retry requests_used = %d, want 2", got)
	}
}

func TestRequestBudgetStopsBeforeDispatch(t *testing.T) {
	var dispatched atomic.Int32
	base := roundTripTestFunc(func(req *http.Request) (*http.Response, error) {
		dispatched.Add(1)
		return &http.Response{
			StatusCode: http.StatusNoContent, Header: make(http.Header),
			Body: http.NoBody, Request: req,
		}, nil
	})
	ctx, cancel, budget := NewBudgetContext(context.Background(), RunLimits{
		RequestLimit: 1, MutationLimit: 0, ElapsedLimit: time.Second,
	})
	defer cancel()
	client := &http.Client{Transport: CountingTransport{Base: base}}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.invalid", nil)
		resp, err := client.Do(req)
		if i == 0 {
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		} else if !errors.Is(err, ErrRequestBudget) {
			t.Fatalf("second dispatch error = %v, want request budget", err)
		}
	}
	if dispatched.Load() != 1 || budget.Snapshot().RequestsUsed != 1 {
		t.Fatalf("dispatched=%d usage=%+v", dispatched.Load(), budget.Snapshot())
	}
}

type roundTripTestFunc func(*http.Request) (*http.Response, error)

func (f roundTripTestFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestMutationAndElapsedBudgets(t *testing.T) {
	ctx, cancel, budget := NewBudgetContext(context.Background(), RunLimits{
		RequestLimit: 0, MutationLimit: 1, ElapsedLimit: 10 * time.Millisecond,
	})
	defer cancel()
	if err := ConsumeMutation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ConsumeMutation(ctx); !errors.Is(err, ErrMutationBudget) {
		t.Fatalf("second mutation error = %v", err)
	}
	<-ctx.Done()
	if err := budget.Exhaustion(ctx); !errors.Is(err, ErrElapsedBudget) {
		t.Fatalf("elapsed exhaustion = %v", err)
	}
}

func TestCleanupContextCannotConsumeOrFlipFrozenForwardBudget(t *testing.T) {
	parent, parentCancel := context.WithCancel(context.Background())
	forwardCtx, cancel, budget := NewBudgetContext(parent, RunLimits{
		RequestLimit: 1, MutationLimit: 1, ElapsedLimit: time.Second,
	})
	defer cancel()
	if err := ConsumeMutation(forwardCtx); err != nil {
		t.Fatal(err)
	}
	base := roundTripTestFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNoContent, Header: make(http.Header),
			Body: http.NoBody, Request: req,
		}, nil
	})
	req, _ := http.NewRequestWithContext(forwardCtx, http.MethodGet, "http://example.invalid", nil)
	resp, err := (&http.Client{Transport: CountingTransport{Base: base}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	frozen, frozenErr := budget.FreezeForward(forwardCtx)
	if frozenErr != nil {
		t.Fatalf("freeze exhaustion = %v", frozenErr)
	}

	parentCancel()
	cleanupCtx, cleanupCancel := budget.CleanupContext(time.Second)
	defer cleanupCancel()
	if cleanupCtx.Err() != nil {
		t.Fatalf("cleanup inherited parent cancellation: %v", cleanupCtx.Err())
	}
	if err := ConsumeMutation(cleanupCtx); err != nil {
		t.Fatalf("cleanup mutation must bypass exhausted forward cap: %v", err)
	}
	req, _ = http.NewRequestWithContext(cleanupCtx, http.MethodGet, "http://example.invalid", nil)
	resp, err = (&http.Client{Transport: CountingTransport{Base: base}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	time.Sleep(10 * time.Millisecond)
	if usage := budget.Snapshot(); usage != frozen {
		t.Fatalf("cleanup changed frozen usage: before=%+v after=%+v", frozen, usage)
	}
	if exhausted := budget.Exhaustion(forwardCtx); exhausted != nil {
		t.Fatalf("cleanup/cancel flipped frozen exhaustion to %v", exhausted)
	}
}

func TestRunReportIsBoundedAndSecretFree(t *testing.T) {
	report := &RunReport{
		ReportVersion: RunReportVersion,
		ScenarioID:    "test", ScenarioVersion: 1,
		CampaignRunID: "run", EngagementID: "eng",
		TargetRef:           "https://example.test/mcp",
		EvidenceFingerprint: strings.Repeat("a", 64),
		Steps:               []StepObservation{},
		Cleanup:             CleanupReport{Status: CleanupNotApplicable, Postcondition: "not_applicable"},
	}
	for i := 0; i < maxReportSteps+3; i++ {
		report.AddStep(StepClassify, "fixed_code")
	}
	if len(report.Steps) != maxReportSteps {
		t.Fatalf("steps = %d, want bounded %d", len(report.Steps), maxReportSteps)
	}
	for index, step := range report.Steps {
		if step.Sequence != index+1 || step.OperationClass == "" {
			t.Fatalf("step %d missing typed sequence/class: %+v", index, step)
		}
		if _, err := time.Parse(time.RFC3339Nano, step.StartedAt); err != nil {
			t.Fatalf("step %d started_at is not RFC3339Nano: %q", index, step.StartedAt)
		}
		if _, err := time.Parse(time.RFC3339Nano, step.CompletedAt); err != nil {
			t.Fatalf("step %d completed_at is not RFC3339Nano: %q", index, step.CompletedAt)
		}
	}
	for _, receiptID := range []string{"opaque-one", "opaque-one", "opaque-two"} {
		report.LinkReceipt(receiptID)
	}
	if len(report.ReceiptRefs) != 2 {
		t.Fatalf("receipt_refs = %v, want bounded unique opaque IDs", report.ReceiptRefs)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"raw-credential",
		"original-content",
		"injected-content",
		"/.agenthound/state/",
		"receipt_path",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("report leaked forbidden value %q", forbidden)
		}
	}
}

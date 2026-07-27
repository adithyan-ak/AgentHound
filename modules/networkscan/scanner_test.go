package networkscan

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// fakeDialer simulates the result of a TCP connect probe without binding any
// real ports. openSet is the set of host:port pairs that should "succeed";
// everything else returns a refused-style error. dialCount lets tests assert
// how many probes were issued (e.g. for cancellation cleanliness).
type fakeDialer struct {
	openSet   map[string]bool
	dialCount int64

	// onDial fires on every DialContext call (BEFORE the openSet lookup) so
	// tests can inject panics or sleeps to exercise probe()'s defer recover()
	// and cancellation handling.
	onDial func(host string, port int)
}

func (f *fakeDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	atomic.AddInt64(&f.dialCount, 1)
	host, portStr, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portStr)
	if f.onDial != nil {
		f.onDial(host, port)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if f.openSet[address] {
		// Return a closed pair so .Close() succeeds and we don't leak FDs.
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
}

type outcomeDialer struct {
	errors map[string]error
}

func (d *outcomeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	return nil, d.errors[address]
}

func TestScanner_HappyPath(t *testing.T) {
	d := &fakeDialer{
		openSet: map[string]bool{
			"10.0.0.5:11434": true, // Ollama on host 5
			"10.0.0.5:4000":  true, // LiteLLM on host 5
			"10.0.0.6:11434": true, // Ollama on host 6
			// Hosts 0..4 and 7 have nothing open.
		},
	}
	s := &Scanner{
		Dialer:  d,
		Timeout: 100 * time.Millisecond,
	}
	targets, err := s.Scan(context.Background(), "10.0.0.0/29")
	if err != nil {
		t.Fatalf("Scan err = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (hosts .5 and .6 had open ports)", len(targets))
	}

	// Find each target by address.
	byAddr := map[string]bool{}
	for _, tg := range targets {
		byAddr[tg.Address] = true
		if tg.Kind != "host" {
			t.Errorf("target.Kind = %q, want host", tg.Kind)
		}
		if _, ok := tg.Meta["open_ports"]; !ok {
			t.Errorf("target %s missing open_ports meta", tg.Address)
		}
		if _, ok := tg.Meta["candidate_kinds"]; !ok {
			t.Errorf("target %s missing candidate_kinds meta", tg.Address)
		}
	}
	if !byAddr["10.0.0.5"] || !byAddr["10.0.0.6"] {
		t.Errorf("missing expected hosts; got %v", byAddr)
	}

	// Host .5 has both Ollama AND LiteLLM open.
	for _, tg := range targets {
		if tg.Address == "10.0.0.5" {
			if !strings.Contains(tg.Meta["candidate_kinds"], "ollama") ||
				!strings.Contains(tg.Meta["candidate_kinds"], "litellm") {
				t.Errorf("host .5 candidate_kinds = %q, want both ollama and litellm",
					tg.Meta["candidate_kinds"])
			}
		}
	}
}

func TestScanner_NoOpenPorts(t *testing.T) {
	d := &fakeDialer{openSet: map[string]bool{}}
	s := &Scanner{Dialer: d, Timeout: 100 * time.Millisecond}
	targets, err := s.Scan(context.Background(), "10.0.0.0/30")
	if err != nil {
		t.Fatalf("Scan err = %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("got %d targets, want 0", len(targets))
	}
	report := s.LastReport()
	if report.State() != ingest.OutcomeComplete ||
		report.Conclusive != report.Total {
		t.Fatalf("refused-port report = %+v, want complete", report)
	}
	wantTargets := LogicalTargetSetIdentity([]string{
		"10.0.0.0",
		"10.0.0.1",
		"10.0.0.2",
		"10.0.0.3",
	})
	if report.Targets != wantTargets {
		t.Fatalf("scheduled targets = %+v, want %+v", report.Targets, wantTargets)
	}
	if len(report.Ports) != len(DefaultPorts) {
		t.Fatalf("scheduled ports = %v, want defaults %v", report.Ports, DefaultPorts)
	}
}

func TestScanner_ProbeOutcomeAccounting(t *testing.T) {
	t.Run("mixed conclusive and unknown is partial", func(t *testing.T) {
		s := &Scanner{
			Ports: []int{7001, 7002},
			Dialer: &outcomeDialer{errors: map[string]error{
				"10.0.0.1:7001": syscall.ECONNREFUSED,
				"10.0.0.1:7002": context.DeadlineExceeded,
			}},
		}
		if _, err := s.Scan(context.Background(), "10.0.0.1"); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		report := s.LastReport()
		if report.State() != ingest.OutcomePartial ||
			report.Total != 2 || report.Conclusive != 1 || report.Unknown() != 1 {
			t.Fatalf("mixed report = %+v (unknown=%d), want partial 2/1/1",
				report, report.Unknown())
		}
	})

	t.Run("nothing conclusive is failed", func(t *testing.T) {
		s := &Scanner{
			Ports: []int{7001, 7002},
			Dialer: &outcomeDialer{errors: map[string]error{
				"10.0.0.1:7001": context.DeadlineExceeded,
				"10.0.0.1:7002": context.DeadlineExceeded,
			}},
		}
		if _, err := s.Scan(context.Background(), "10.0.0.1"); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		report := s.LastReport()
		if report.State() != ingest.OutcomeFailed ||
			report.Total != 2 || report.Conclusive != 0 || report.Unknown() != 2 {
			t.Fatalf("unknown-only report = %+v (unknown=%d), want failed 2/0/2",
				report, report.Unknown())
		}
	})
}

func TestScanner_CustomPorts(t *testing.T) {
	d := &fakeDialer{
		openSet: map[string]bool{
			"10.0.0.1:9999": true,
		},
	}
	s := &Scanner{
		Dialer:  d,
		Timeout: 100 * time.Millisecond,
		Ports:   []int{9999, 7777},
	}
	targets, err := s.Scan(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	report := s.LastReport()
	if !slices.Equal(report.Ports, []int{9999, 7777}) {
		t.Fatalf("scheduled ports = %v, want [9999 7777]", report.Ports)
	}
	if report.Targets != LogicalTargetSetIdentity([]string{"10.0.0.1"}) {
		t.Fatalf("scheduled targets = %+v", report.Targets)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].Meta["open_ports"] != "9999" {
		t.Errorf("open_ports = %q, want 9999", targets[0].Meta["open_ports"])
	}
	// 9999 has no entry in PortToKind; candidate_kinds should be empty.
	if targets[0].Meta["candidate_kinds"] != "" {
		t.Errorf("candidate_kinds = %q, want empty", targets[0].Meta["candidate_kinds"])
	}
}

// TestScanner_Cancellation feeds a CIDR large enough that the producer needs
// to send hundreds of tasks, cancels mid-flight, and asserts the scanner
// returns ctx.Err() with a partial-or-empty result rather than blocking
// forever or panicking. The exact target count is non-deterministic — the
// test only asserts cancellation is observed and the scanner shuts down
// cleanly.
func TestScanner_Cancellation(t *testing.T) {
	d := &fakeDialer{
		openSet: map[string]bool{},
		onDial: func(host string, port int) {
			// Slow down each dial so cancellation has time to fire.
			time.Sleep(20 * time.Millisecond)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	s := &Scanner{
		Dialer:      d,
		Timeout:     500 * time.Millisecond,
		Concurrency: 4, // small pool so the queue accumulates
	}
	_, err := s.Scan(ctx, "10.0.0.0/24") // 256 hosts × 7 ports = 1792 tasks
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	// Total dial count should be a fraction of the full 1792 — proves the
	// producer stopped enqueueing after cancel. (Cancel happens at ~50ms;
	// each dial is ~20ms; 4 workers; roughly ~10 dials before cancel.)
	if atomic.LoadInt64(&d.dialCount) >= 1792 {
		t.Errorf("dialCount = %d; expected partial after cancel", d.dialCount)
	}
}

// TestScanner_PanicIsolation injects a dial that panics on the first port
// for the first host. The panic must NOT take down the worker pool; later
// probes for other hosts/ports should still complete, and the scanner
// returns the partial result.
func TestScanner_PanicIsolation(t *testing.T) {
	var panicked atomic.Bool
	d := &fakeDialer{
		openSet: map[string]bool{
			"10.0.0.2:11434": true,
		},
		onDial: func(host string, port int) {
			// Panic on the very first probe of host .1 only.
			if host == "10.0.0.1" && port == 11434 && !panicked.Swap(true) {
				panic("simulated dialer crash")
			}
		},
	}
	s := &Scanner{
		Dialer:      d,
		Timeout:     100 * time.Millisecond,
		Concurrency: 2,
	}
	// CIDR 10.0.0.0/30 → hosts .0, .1, .2, .3.
	targets, err := s.Scan(context.Background(), "10.0.0.0/30")
	if err != nil {
		t.Fatalf("Scan returned err = %v; expected nil despite panic", err)
	}
	// Host .2 should still produce a target.
	found := false
	for _, tg := range targets {
		if tg.Address == "10.0.0.2" {
			found = true
		}
	}
	if !found {
		t.Errorf("host 10.0.0.2 missing from targets; pool may have died after panic. targets=%v", targets)
	}
	if !panicked.Load() {
		t.Error("panic was not triggered (test setup wrong)")
	}
}

// TestScanner_ProgressReported verifies the optional Progress hook fires and
// that the final sample reports every probe complete (done == total ==
// hosts × ports). A /30 is 4 hosts × the 7 default ports = 28 probes.
func TestScanner_ProgressReported(t *testing.T) {
	d := &fakeDialer{openSet: map[string]bool{"10.0.0.1:11434": true}}

	var mu sync.Mutex
	var calls [][2]int
	s := &Scanner{
		Dialer:  d,
		Timeout: 100 * time.Millisecond,
		Progress: func(done, total int) {
			mu.Lock()
			calls = append(calls, [2]int{done, total})
			mu.Unlock()
		},
	}

	if _, err := s.Scan(context.Background(), "10.0.0.0/30"); err != nil {
		t.Fatalf("Scan err = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) == 0 {
		t.Fatal("Progress was never called")
	}
	wantTotal := 4 * len(DefaultPorts)
	last := calls[len(calls)-1]
	if last[0] != wantTotal || last[1] != wantTotal {
		t.Errorf("final progress = [%d %d], want [%d %d]", last[0], last[1], wantTotal, wantTotal)
	}
}

// TestScanner_NoProgressHook is a guard that a nil Progress field is the safe
// default — Scan must complete normally without ever touching the hook.
func TestScanner_NoProgressHook(t *testing.T) {
	d := &fakeDialer{openSet: map[string]bool{"10.0.0.1:11434": true}}
	s := &Scanner{Dialer: d, Timeout: 100 * time.Millisecond}
	targets, err := s.Scan(context.Background(), "10.0.0.0/30")
	if err != nil {
		t.Fatalf("Scan err = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
}

// TestScanner_ConcurrencyClamped is the A2 regression: an absurd Concurrency
// must be clamped to MaxConcurrency so the tasks channel (concurrency*2) does
// not overflow to a negative size (panic on 32-bit) or allocate an enormous
// buffer (OOM on 64-bit). With the clamp the scan completes normally.
func TestScanner_ConcurrencyClamped(t *testing.T) {
	d := &fakeDialer{openSet: map[string]bool{}}
	s := &Scanner{
		Dialer:      d,
		Timeout:     50 * time.Millisecond,
		Concurrency: 1 << 30, // ~1.07e9; *2 would be ~51 GiB of channel buffer
	}
	if _, err := s.Scan(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("Scan with huge Concurrency err = %v; clamp should prevent panic/OOM", err)
	}
}

func TestScanner_ExpandError(t *testing.T) {
	// Public CIDR without --allow-public-targets returns the expand error
	// without calling the dialer.
	d := &fakeDialer{}
	s := &Scanner{Dialer: d, Timeout: 100 * time.Millisecond}
	_, err := s.Scan(context.Background(), "1.1.1.1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "expand") {
		t.Errorf("err = %v, want one containing 'expand'", err)
	}
	if atomic.LoadInt64(&d.dialCount) != 0 {
		t.Errorf("dialCount = %d; dialer should not be called when expand fails", d.dialCount)
	}
}

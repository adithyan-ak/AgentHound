package networkscan

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

// DefaultPorts is the default AI-service port set. Order does not matter;
// the scanner probes each independently.
//
// Every open endpoint is evaluated by every registered fingerprinter. These
// defaults remain useful ordering hints and avoid sweeping all 65,535 ports.
var DefaultPorts = []int{
	11434, // Ollama
	8000,  // vLLM AND LangServe (port collision is intentional; fingerprint dispatch resolves)
	6333,  // Qdrant
	5000,  // MLflow
	4000,  // LiteLLM
	8888,  // Jupyter
	3000,  // Open WebUI
}

const (
	DefaultConcurrency  = 50
	DefaultProbeTimeout = 3 * time.Second

	// MaxConcurrency caps the worker pool. It bounds the goroutine count and,
	// critically, the tasks-channel size (concurrency*2): without it an absurd
	// --network-scan-concurrency overflows that multiply to a negative int on
	// 32-bit (make(chan) panics) or allocates an enormous buffer on 64-bit.
	MaxConcurrency = 4096
)

// PortToKind maps each AI-service default port to its candidate service-kind
// tags. Port 8000 is shared between vLLM and LangServe, so it maps to BOTH
// kinds; dispatch tries hinted fingerprinters first, then every remaining
// fingerprinter. Operators can override the port set entirely via --ports.
var PortToKind = map[int][]string{
	11434: {"ollama"},
	8000:  {"vllm", "langserve"},
	6333:  {"qdrant"},
	5000:  {"mlflow"},
	4000:  {"litellm"},
	8888:  {"jupyter"},
	3000:  {"openwebui"},
}

// dialer is the interface tests substitute to exercise the worker pool
// without binding real ports. The default is *net.Dialer.
type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Scanner expands a single CIDR / host spec into a per-host list of
// targets after probing the configured port set. It conforms to
// sdk/action.Scanner; the registered network.scan module returns this
// type from sdk/module.GetByTarget("network", action.Scan).
//
// Each Target's Meta map carries:
//   - "open_ports": comma-separated list of open ports (e.g. "11434,4000")
//   - "candidate_kinds": comma-separated AI-service kinds the open ports
//     hint at (e.g. "ollama,litellm"); fingerprinters consume this to
//     decide which probe to run first
//
// The scanner does not emit ingest JSON; the CLI dispatches fingerprinters on
// these targets and adds their nodes to the network-scan envelope.
type Scanner struct {
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	ExpandOpts  ExpandOptions

	// Dialer is overridable in tests so the worker pool can be exercised
	// without binding to real ports. nil → net.Dialer with Timeout.
	Dialer dialer

	// Progress, if non-nil, is called periodically with the number of
	// completed probes and the total probe count (hosts × ports). It is
	// invoked from a single dedicated goroutine on a fixed cadence, plus
	// once at the end, so implementations may render directly without
	// locking. nil disables progress reporting (the default).
	Progress func(done, total int)
}

// hostResult aggregates open ports for a single host with mutex-protected
// concurrent access from the worker pool. Defined at package scope so
// probe() can take a typed pointer rather than threading an interface.
type hostResult struct {
	mu        sync.Mutex
	openPorts []int
}

func (h *hostResult) appendPort(p int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.openPorts = append(h.openPorts, p)
}

// Scan expands the spec, then probes each host's configured ports in
// parallel via a fixed-size worker pool. Hosts with no open ports are
// dropped; hosts with at least one open port produce one Target.
//
// Returns the targets and a non-nil error only if the expansion itself
// failed. Probe failures (connection refused, timeout) are normal and
// silent. Context cancellation returns a partial result plus
// context.Canceled so the operator's --output can still be written.
func (s *Scanner) Scan(ctx context.Context, cidr string) ([]action.Target, error) {
	hosts, err := Expand(cidr, s.ExpandOpts)
	if err != nil {
		return nil, fmt.Errorf("expand %q: %w", cidr, err)
	}

	ports := s.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}

	concurrency := s.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > MaxConcurrency {
		concurrency = MaxConcurrency
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}

	d := s.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: timeout}
	}

	results := make(map[string]*hostResult, len(hosts))
	for _, h := range hosts {
		results[h] = &hostResult{}
	}

	type probeTask struct {
		host string
		port int
	}
	tasks := make(chan probeTask, concurrency*2)

	// Progress accounting: workers bump completed after each probe; a single
	// reporter goroutine samples it on a fixed cadence so rendering never
	// contends with the worker pool. Guarded so a nil Progress costs nothing.
	total := len(hosts) * len(ports)
	var completed atomic.Int64
	var stopReporter, reporterDone chan struct{}
	if s.Progress != nil && total > 0 {
		stopReporter = make(chan struct{})
		reporterDone = make(chan struct{})
		go func() {
			defer close(reporterDone)
			ticker := time.NewTicker(150 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopReporter:
					return
				case <-ticker.C:
					s.Progress(int(completed.Load()), total)
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				probe(ctx, d, t.host, t.port, timeout, results[t.host])
				completed.Add(1)
			}
		}()
	}

	cancelled := false
producer:
	for _, host := range hosts {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				cancelled = true
				break producer
			case tasks <- probeTask{host: host, port: port}:
			}
		}
	}
	close(tasks)
	wg.Wait()

	// Stop the reporter and emit one final sample. Receiving on reporterDone
	// guarantees the ticker goroutine has returned, so this last call can
	// never race with it. On a clean run completed == total (every probe ran);
	// on cancellation it reflects the partial count.
	if s.Progress != nil && total > 0 {
		close(stopReporter)
		<-reporterDone
		s.Progress(int(completed.Load()), total)
	}

	var out []action.Target
	for _, host := range hosts {
		r := results[host]
		if len(r.openPorts) == 0 {
			continue
		}
		out = append(out, hostResultToTarget(host, r.openPorts, ports))
	}

	if cancelled {
		return out, ctx.Err()
	}
	return out, nil
}

// probe attempts a TCP connect to host:port within the timeout and
// records the port on the result struct if the connection succeeds.
// It is the only function in this file that does network IO; tests
// substitute the dialer to exercise the worker pool deterministically.
//
// Wrapped in defer recover() so a misbehaving dialer can't crash the
// worker pool — the surrounding Scan call should still return useful
// partial results.
func probe(ctx context.Context, d dialer, host string, port int, timeout time.Duration, r *hostResult) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("scanner probe panicked", "host", host, "port", port, "panic", rec)
		}
	}()

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return
	}
	_ = conn.Close()
	r.appendPort(port)
}

// hostResultToTarget assembles the final Target per host. The
// candidate_kinds list is populated using PortToKind so fingerprinters
// can shortcut their probe order.
func hostResultToTarget(host string, openPorts, configuredPorts []int) action.Target {
	sortedOpen := sortByConfiguredOrder(openPorts, configuredPorts)

	var kinds []string
	for _, p := range sortedOpen {
		if ks, ok := PortToKind[p]; ok {
			kinds = append(kinds, ks...)
		}
	}

	return action.Target{
		Kind:    "host",
		Address: host,
		Meta: map[string]string{
			"open_ports":      joinInts(sortedOpen, ","),
			"candidate_kinds": joinStrings(kinds, ","),
		},
	}
}

// sortByConfiguredOrder reorders openPorts to match the order in
// configuredPorts. Ports not in the configured list (shouldn't happen,
// defensive) are dropped.
func sortByConfiguredOrder(open, configured []int) []int {
	openSet := make(map[int]bool, len(open))
	for _, p := range open {
		openSet[p] = true
	}
	out := make([]int, 0, len(open))
	for _, p := range configured {
		if openSet[p] {
			out = append(out, p)
		}
	}
	return out
}

func joinInts(ints []int, sep string) string {
	if len(ints) == 0 {
		return ""
	}
	parts := make([]string, len(ints))
	for i, v := range ints {
		parts[i] = strconv.Itoa(v)
	}
	return joinStrings(parts, sep)
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}

// Compile-time assertion: Scanner conforms to sdk/action.Scanner.
var _ action.Scanner = (*Scanner)(nil)

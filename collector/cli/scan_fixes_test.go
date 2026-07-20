package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

// --- Mock Fingerprinter (Finding 6) ---

type mockFingerprinter struct {
	targetKind  string
	gotAddress  string
	probeCount  int
	matchedNode string
}

func (m *mockFingerprinter) ID() string            { return "mock.fingerprint." + m.targetKind }
func (m *mockFingerprinter) Action() action.Action { return action.Fingerprint }
func (m *mockFingerprinter) Target() string        { return m.targetKind }
func (m *mockFingerprinter) Description() string   { return "mock fingerprinter" }
func (m *mockFingerprinter) Version() string       { return "0.0.0" }
func (m *mockFingerprinter) IsDestructive() bool   { return false }
func (m *mockFingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	m.probeCount++
	m.gotAddress = t.Address
	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: m.targetKind,
		IngestData: &ingest.IngestData{
			Graph: ingest.GraphData{
				Nodes: []ingest.Node{{ID: m.matchedNode, Kinds: []string{"AIService"}}},
			},
		},
	}, nil
}

// TestDispatchFingerprints_DerivesKindFromPort is the Finding 6 regression.
// With custom --ports producing an unmapped port (9999) BEFORE a mapped one
// (4000 → litellm), the old index-zip logic paired kinds[0]="litellm" with
// ports[0]="9999" and probed the wrong port. The fix derives the kind per
// port via networkscan.PortToKind, so the litellm fingerprinter must be
// dispatched against :4000, not :9999.
func TestDispatchFingerprints_DerivesKindFromPort(t *testing.T) {
	fp := &mockFingerprinter{targetKind: "litellm", matchedNode: "sha256:litellm-node"}

	// open_ports lists the unmapped port FIRST; candidate_kinds lists only
	// the mapped kind (mirrors hostResultToTarget's real output).
	targets := []action.Target{{
		Kind:    "host",
		Address: "10.0.0.7",
		Meta: map[string]string{
			"open_ports":      "9999,4000",
			"candidate_kinds": "litellm",
		},
	}}

	envelope := fingerprintTestEnvelope()
	dispatchFingerprintCandidates(context.Background(), io.Discard, targets, envelope, false, 1, time.Second, "test", []fingerprintCandidate{{
		id: fp.ID(), target: fp.Target(), fp: fp,
	}})

	if fp.probeCount != 2 {
		t.Fatalf("fingerprinter probed %d time(s), want once per open endpoint", fp.probeCount)
	}
	if fp.gotAddress != "10.0.0.7:4000" {
		t.Errorf("fingerprinter probed %q, want 10.0.0.7:4000 (port derived from PortToKind)", fp.gotAddress)
	}
	if len(envelope.Graph.Nodes) != 2 || envelope.Graph.Nodes[0].ID != "sha256:litellm-node" || envelope.Graph.Nodes[1].ID != "sha256:litellm-node" {
		t.Errorf("matched node not merged into envelope: %+v", envelope.Graph.Nodes)
	}
}

// conditionalFingerprinter is a mock that only reports Matched when its
// shouldMatch flag is set, so a dispatch test can prove that BOTH candidate
// kinds for a multi-kind port are probed while only the matching one emits.
type conditionalFingerprinter struct {
	targetKind  string
	shouldMatch bool
	probeCount  int
	gotAddress  string
	matchedNode string
}

type failingFingerprinter struct{ targetKind string }

type deadlineWitnessFingerprinter struct {
	calls           atomic.Int32
	secondRemaining chan time.Duration
}

func (m *failingFingerprinter) ID() string            { return "failing.fingerprint." + m.targetKind }
func (m *failingFingerprinter) Action() action.Action { return action.Fingerprint }
func (m *failingFingerprinter) Target() string        { return m.targetKind }
func (m *failingFingerprinter) Description() string   { return "failing fingerprinter" }
func (m *failingFingerprinter) Version() string       { return "0.0.0" }
func (m *failingFingerprinter) IsDestructive() bool   { return false }
func (m *failingFingerprinter) Fingerprint(context.Context, action.Target) (*action.FingerprintResult, error) {
	return &action.FingerprintResult{Matched: false}, errors.New("transport failure")
}

func (m *deadlineWitnessFingerprinter) ID() string            { return "deadline-witness" }
func (m *deadlineWitnessFingerprinter) Action() action.Action { return action.Fingerprint }
func (m *deadlineWitnessFingerprinter) Target() string        { return "deadline" }
func (m *deadlineWitnessFingerprinter) Description() string   { return "deadline witness" }
func (m *deadlineWitnessFingerprinter) Version() string       { return "0.0.0" }
func (m *deadlineWitnessFingerprinter) IsDestructive() bool   { return false }
func (m *deadlineWitnessFingerprinter) Fingerprint(ctx context.Context, _ action.Target) (*action.FingerprintResult, error) {
	if m.calls.Add(1) == 1 {
		<-ctx.Done()
		return &action.FingerprintResult{Matched: false}, ctx.Err()
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("missing task deadline")
	}
	m.secondRemaining <- time.Until(deadline)
	return &action.FingerprintResult{Matched: false}, nil
}

func (m *conditionalFingerprinter) ID() string            { return "cond.fingerprint." + m.targetKind }
func (m *conditionalFingerprinter) Action() action.Action { return action.Fingerprint }
func (m *conditionalFingerprinter) Target() string        { return m.targetKind }
func (m *conditionalFingerprinter) Description() string   { return "conditional mock fingerprinter" }
func (m *conditionalFingerprinter) Version() string       { return "0.0.0" }
func (m *conditionalFingerprinter) IsDestructive() bool   { return false }
func (m *conditionalFingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	m.probeCount++
	m.gotAddress = t.Address
	if !m.shouldMatch {
		return &action.FingerprintResult{Matched: false}, nil
	}
	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: m.targetKind,
		IngestData: &ingest.IngestData{
			Graph: ingest.GraphData{
				Nodes: []ingest.Node{{ID: m.matchedNode, Kinds: []string{"AIService"}}},
			},
		},
	}, nil
}

// TestPortToKind_8000IsMultiKind locks in that port 8000 maps to BOTH vLLM and
// LangServe. Before the fix it was a single string "vllm", which made
// langservefp dead code on the scan path.
func TestPortToKind_8000IsMultiKind(t *testing.T) {
	kinds := networkscan.PortToKind[8000]
	want := map[string]bool{"vllm": false, "langserve": false}
	for _, k := range kinds {
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("PortToKind[8000] = %v, missing kind %q", kinds, k)
		}
	}
}

// TestDispatchFingerprints_TriesAllCandidateKinds is the Finding 2 regression.
// Port 8000 maps to both "vllm" and "langserve". dispatchFingerprints must
// probe BOTH candidate kinds, not just the first. Here vLLM does not match and
// LangServe does, so the LangServe node must still be emitted — proving the
// second candidate is reached.
func TestDispatchFingerprints_TriesAllCandidateKinds(t *testing.T) {
	vllm := &conditionalFingerprinter{targetKind: "vllm", shouldMatch: false}
	langserve := &conditionalFingerprinter{targetKind: "langserve", shouldMatch: true, matchedNode: "sha256:langserve-node"}

	targets := []action.Target{{
		Kind:    "host",
		Address: "10.0.0.9",
		Meta: map[string]string{
			"open_ports":      "8000",
			"candidate_kinds": "vllm,langserve",
		},
	}}

	envelope := fingerprintTestEnvelope()
	dispatchFingerprintCandidates(context.Background(), io.Discard, targets, envelope, false, 1, time.Second, "test", []fingerprintCandidate{
		{id: vllm.ID(), target: vllm.Target(), fp: vllm},
		{id: langserve.ID(), target: langserve.Target(), fp: langserve},
	})

	if vllm.probeCount != 1 {
		t.Errorf("vllm probed %d time(s), want exactly 1", vllm.probeCount)
	}
	if langserve.probeCount != 1 {
		t.Errorf("langserve probed %d time(s), want exactly 1 (second candidate must be reached)", langserve.probeCount)
	}
	if vllm.gotAddress != "10.0.0.9:8000" || langserve.gotAddress != "10.0.0.9:8000" {
		t.Errorf("dispatch addresses: vllm=%q langserve=%q, want both 10.0.0.9:8000", vllm.gotAddress, langserve.gotAddress)
	}
	if len(envelope.Graph.Nodes) != 1 || envelope.Graph.Nodes[0].ID != "sha256:langserve-node" {
		t.Errorf("LangServe node not merged into envelope: %+v", envelope.Graph.Nodes)
	}
}

func TestFingerprintCoverageDistinguishesFailureFromNoMatch(t *testing.T) {
	targets := []action.Target{{Kind: "host", Address: "10.0.0.9", Meta: map[string]string{"open_ports": "9999"}}}
	noMatch := &conditionalFingerprinter{targetKind: "nomatch"}
	envelope := fingerprintTestEnvelope()
	dispatchFingerprintCandidates(context.Background(), io.Discard, targets, envelope, true, 1, time.Second, "test", []fingerprintCandidate{{
		id: noMatch.ID(), target: noMatch.Target(), fp: noMatch,
	}})
	outcome := envelope.Meta.Collection.Outcomes[len(envelope.Meta.Collection.Outcomes)-1]
	if outcome.State != ingest.OutcomeComplete || outcome.Items != 1 {
		t.Fatalf("definitive no-match outcome = %+v", outcome)
	}
	if len(ingest.CompleteCoverageDomains(envelope.Meta.Collection)) != 1 {
		t.Fatalf("definitive no-match did not permit reconciliation: %+v", envelope.Meta.Collection)
	}

	failure := &failingFingerprinter{targetKind: "failure"}
	envelope = fingerprintTestEnvelope()
	dispatchFingerprintCandidates(context.Background(), io.Discard, targets, envelope, true, 1, time.Second, "test", []fingerprintCandidate{{
		id: failure.ID(), target: failure.Target(), fp: failure,
	}})
	outcome = envelope.Meta.Collection.Outcomes[len(envelope.Meta.Collection.Outcomes)-1]
	if outcome.State != ingest.OutcomePartial || outcome.Items != 0 {
		t.Fatalf("operational failure outcome = %+v", outcome)
	}
	if len(ingest.CompleteCoverageDomains(envelope.Meta.Collection)) != 0 {
		t.Fatalf("indeterminate fingerprint could reconcile prior services: %+v", envelope.Meta.Collection)
	}
}

func TestFingerprintDeadlineStartsWhenWorkerDequeues(t *testing.T) {
	targets := []action.Target{
		{Kind: "host", Address: "10.0.0.10", Meta: map[string]string{"open_ports": "9998"}},
		{Kind: "host", Address: "10.0.0.11", Meta: map[string]string{"open_ports": "9999"}},
	}
	fp := &deadlineWitnessFingerprinter{secondRemaining: make(chan time.Duration, 1)}
	envelope := fingerprintTestEnvelope()
	dispatchFingerprintCandidates(context.Background(), io.Discard, targets, envelope, true, 1, 80*time.Millisecond, "test", []fingerprintCandidate{{
		id: fp.ID(), target: fp.Target(), fp: fp,
	}})
	remaining := <-fp.secondRemaining
	if remaining < 50*time.Millisecond {
		t.Fatalf("queued task inherited queue delay; remaining deadline = %v", remaining)
	}
	outcome := envelope.Meta.Collection.Outcomes[len(envelope.Meta.Collection.Outcomes)-1]
	if outcome.State != ingest.OutcomePartial || outcome.Items != 1 {
		t.Fatalf("deadline outcome = %+v", outcome)
	}
}

func TestFingerprintEndpointsAndWorkersAreClamped(t *testing.T) {
	if got := normalizeFingerprintWorkers(4096); got != maxFingerprintWorkers {
		t.Fatalf("HTTP workers = %d, want cap %d", got, maxFingerprintWorkers)
	}
	fp := &conditionalFingerprinter{targetKind: "dedupe"}
	targets := []action.Target{
		{Kind: "host", Address: "10.0.0.12", Meta: map[string]string{"open_ports": "9999,9999,0,70000,invalid"}},
		{Kind: "host", Address: "10.0.0.12", Meta: map[string]string{"open_ports": "9999"}},
	}
	dispatchFingerprintCandidates(context.Background(), io.Discard, targets, fingerprintTestEnvelope(), true, 4096, 0, "test", []fingerprintCandidate{{
		id: fp.ID(), target: fp.Target(), fp: fp,
	}})
	if fp.probeCount != 1 {
		t.Fatalf("duplicate endpoint probed %d times, want once", fp.probeCount)
	}
}

func TestOrderedFingerprintersUsesPortHintsOnlyForPriority(t *testing.T) {
	candidates := []fingerprintCandidate{
		{id: "a-unmapped", target: "custom"},
		{id: "b-langserve", target: "langserve"},
		{id: "c-vllm", target: "vllm"},
	}
	got := orderedFingerprinters(8000, candidates)
	want := []string{"c-vllm", "b-langserve", "a-unmapped"}
	for i := range want {
		if got[i].id != want[i] {
			t.Fatalf("candidate order = %v, want %v", []string{got[0].id, got[1].id, got[2].id}, want)
		}
	}
}

// TestRunScan_URLWithoutMCP is the Finding 7 regression: `scan --url <srv>`
// with no explicit mode flag must infer MCP-only mode and not trip the
// "--url requires --mcp" guard. We point --url at a closed local address so
// the MCP collector returns quickly (its error is logged, not fatal) and
// assert runScan returns nil and writes the artifact.
func TestRunScan_URLWithoutMCP(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "url-only.json")

	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "url", "http://127.0.0.1:1")
	mustSetFlag(t, cmd, "scan-output", out)

	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("runScan with --url and no mode flags: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected artifact at %s: %v", out, err)
	}
}

func TestCollectMCP_DefaultLogsRedactTargetURLSecrets(t *testing.T) {
	const rawURL = "http://url-user:url-pass@127.0.0.1:1/mcp?api_key=url-query-secret#url-fragment-secret"
	const safeURL = "http://127.0.0.1:1/mcp"

	for _, tc := range []struct {
		name    string
		jsonLog bool
	}{
		{name: "text"},
		{name: "json", jsonLog: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureMCPCollectionLogs(t, tc.jsonLog, rawURL)
			if !strings.Contains(logs, safeURL) {
				t.Fatalf("logs do not contain sanitized endpoint %q: %s", safeURL, logs)
			}
			for _, secret := range []string{
				rawURL,
				"url-user",
				"url-pass",
				"url-query-secret",
				"url-fragment-secret",
			} {
				if strings.Contains(logs, secret) {
					t.Fatalf("default %s logs leaked %q: %s", tc.name, secret, logs)
				}
			}
		})
	}
}

func captureMCPCollectionLogs(t *testing.T, jsonLog bool, rawURL string) string {
	t.Helper()

	previousLogger := slog.Default()
	previousStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr capture pipe: %v", err)
	}
	os.Stderr = writer
	setupLogger("info", false, jsonLog)

	defer func() {
		slog.SetDefault(previousLogger)
		os.Stderr = previousStderr
		_ = writer.Close()
		_ = reader.Close()
	}()

	_, _ = collectMCP(
		context.Background(),
		testCollectionOrigin,
		rawURL,
		"",
		1,
		100*time.Millisecond,
		false,
		"log-redaction-test",
		nil,
	)
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr capture: %v", err)
	}
	os.Stderr = previousStderr
	slog.SetDefault(previousLogger)

	logs, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr capture: %v", err)
	}
	return string(logs)
}

// TestRunScan_ExplicitConfigWithURLStillErrors confirms the Finding 7 fix
// preserves the legitimate usage error: explicit --config combined with
// --url remains rejected.
func TestRunScan_ExplicitConfigWithURLStillErrors(t *testing.T) {
	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "url", "http://example.com")
	err := runScan(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--url requires --mcp") {
		t.Fatalf("expected '--url requires --mcp', got: %v", err)
	}
}

// TestResolveScanConcurrency is the Finding 9 regression: the root
// --concurrency / AGENTHOUND_CONCURRENCY value (resolved onto cfg.Concurrency)
// must be honored when --scan-concurrency is unset, while an explicit
// --scan-concurrency always wins.
func TestResolveScanConcurrency(t *testing.T) {
	tests := []struct {
		name            string
		scanConcurrency int
		changed         bool
		cfgConcurrency  int
		want            int
	}{
		{"root fallback when scan-concurrency unset", 5, false, 17, 17},
		{"explicit scan-concurrency wins", 9, true, 17, 9},
		{"scan-concurrency default when cfg is zero", 5, false, 0, 5},
		{"explicit scan-concurrency wins even when cfg unset", 9, true, 0, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveScanConcurrency(tt.scanConcurrency, tt.changed, tt.cfgConcurrency)
			if got != tt.want {
				t.Errorf("resolveScanConcurrency(%d, %v, %d) = %d, want %d",
					tt.scanConcurrency, tt.changed, tt.cfgConcurrency, got, tt.want)
			}
		})
	}
}

// TestResolveProbeTimeout is the Fix #3 regression: network mode must fall back
// to networkscan.DefaultProbeTimeout (3s) when --timeout is unchanged, rather
// than inheriting the shared flag's 120s default (tuned for the legacy
// per-server MCP/A2A collectors). An explicit --timeout always wins.
func TestResolveProbeTimeout(t *testing.T) {
	if got := resolveProbeTimeout(120*time.Second, false); got != networkscan.DefaultProbeTimeout {
		t.Errorf("unchanged --timeout: got %v, want %v (networkscan default)", got, networkscan.DefaultProbeTimeout)
	}
	if got := resolveProbeTimeout(10*time.Second, true); got != 10*time.Second {
		t.Errorf("explicit --timeout: got %v, want 10s", got)
	}
	if got := resolveProbeTimeout(0, true); got != networkscan.DefaultProbeTimeout {
		t.Errorf("non-positive TCP timeout: got %v, want %v", got, networkscan.DefaultProbeTimeout)
	}
	if got := resolveFingerprintTimeout(120*time.Second, false); got != 5*time.Second {
		t.Errorf("default HTTP timeout: got %v, want 5s", got)
	}
	if got := resolveFingerprintTimeout(-time.Second, true); got != 5*time.Second {
		t.Errorf("non-positive HTTP timeout: got %v, want 5s", got)
	}
	for _, test := range []struct{ input, want int }{{0, 50}, {-1, 50}, {63, 63}, {5000, networkscan.MaxConcurrency}} {
		if got := normalizeNetworkConcurrency(test.input); got != test.want {
			t.Errorf("normalizeNetworkConcurrency(%d) = %d, want %d", test.input, got, test.want)
		}
	}
}

// TestRequireAuthorizedPrompt locks in the fail-closed behavior referenced by
// the (Fix #5) corrected comment: only an exact "AUTHORIZED" proceeds; empty/
// EOF stdin and any other input abort. It also documents that the prompt is
// spec-independent (it always runs when invoked, never skipping for a private
// spec) — matching the code, not the old misleading comment.
func TestRequireAuthorizedPrompt(t *testing.T) {
	cases := []struct {
		name    string
		stdin   string
		wantErr bool
	}{
		{"eof empty aborts", "", true},
		{"wrong word aborts", "yes\n", true},
		{"lowercase aborts", "authorized\n", true},
		{"exact proceeds", "AUTHORIZED\n", false},
		{"exact without newline proceeds", "AUTHORIZED", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out strings.Builder
			err := requireAuthorizedPrompt("10.0.0.0/24", &out, strings.NewReader(c.stdin))
			if (err != nil) != c.wantErr {
				t.Errorf("stdin=%q err=%v, wantErr=%v", c.stdin, err, c.wantErr)
			}
		})
	}
}

// nonFingerprinterModule is registered for action.Fingerprint but does NOT
// implement action.Fingerprinter (no Fingerprint method) — a misregistration
// the count/dispatch paths must both skip.
type nonFingerprinterModule struct{ kind string }

func (m *nonFingerprinterModule) ID() string            { return "nonfp." + m.kind }
func (m *nonFingerprinterModule) Action() action.Action { return action.Fingerprint }
func (m *nonFingerprinterModule) Target() string        { return m.kind }
func (m *nonFingerprinterModule) Description() string   { return "not a fingerprinter" }
func (m *nonFingerprinterModule) Version() string       { return "0.0.0" }
func (m *nonFingerprinterModule) IsDestructive() bool   { return false }

// TestCountFingerprintProbes_RequiresFingerprinter is the A3 regression: the
// progress denominator must apply the same action.Fingerprinter type assertion
// dispatchFingerprints does, so a module registered for Fingerprint that does
// not implement the interface is not counted.
func TestCountFingerprintProbes_RequiresFingerprinter(t *testing.T) {
	m := &nonFingerprinterModule{kind: "ollama"} // port 11434 -> "ollama"
	module.Register(m)
	defer deregisterModule(t, m.ID())

	for _, candidate := range registeredFingerprinters() {
		if candidate.id == m.ID() {
			t.Fatalf("non-Fingerprinter %q was included in the candidate list", m.ID())
		}
	}
}

// metaMutatingFingerprinter writes to the Target's Meta during Fingerprint.
type metaMutatingFingerprinter struct{ kind string }

func (m *metaMutatingFingerprinter) ID() string            { return "mutfp." + m.kind }
func (m *metaMutatingFingerprinter) Action() action.Action { return action.Fingerprint }
func (m *metaMutatingFingerprinter) Target() string        { return m.kind }
func (m *metaMutatingFingerprinter) Description() string   { return "meta-mutating fingerprinter" }
func (m *metaMutatingFingerprinter) Version() string       { return "0.0.0" }
func (m *metaMutatingFingerprinter) IsDestructive() bool   { return false }
func (m *metaMutatingFingerprinter) Fingerprint(_ context.Context, t action.Target) (*action.FingerprintResult, error) {
	t.Meta["mutated"] = "yes" // would corrupt sibling probes if Meta were shared
	return &action.FingerprintResult{Matched: false}, nil
}

// TestDispatchFingerprints_MetaCopyIsolatesProbes is the A4 regression: each
// fingerprinter must receive its own copy of Meta, so a mutation cannot leak
// back into the shared target map (or sibling probes).
func TestDispatchFingerprints_MetaCopyIsolatesProbes(t *testing.T) {
	fp := &metaMutatingFingerprinter{kind: "ollama"}

	orig := map[string]string{"open_ports": "11434", "candidate_kinds": "ollama"}
	targets := []action.Target{{Kind: "host", Address: "10.0.0.1", Meta: orig}}

	dispatchFingerprintCandidates(context.Background(), io.Discard, targets, fingerprintTestEnvelope(), true, 1, time.Second, "test", []fingerprintCandidate{{
		id: fp.ID(), target: fp.Target(), fp: fp,
	}})

	if _, leaked := orig["mutated"]; leaked {
		t.Errorf("fingerprinter mutation leaked into the shared target Meta: %v", orig)
	}
}

// TestAllCollectorsFailed is the Finding 12 regression: scan must exit
// non-zero only when EVERY enabled collector errored. Partial success and a
// legitimately empty-but-successful scan (zero enabled, or zero failed) must
// exit 0 — the decision keys on collector errors, never node count.
func TestAllCollectorsFailed(t *testing.T) {
	tests := []struct {
		name    string
		enabled int
		failed  int
		want    bool
	}{
		{"all failed", 2, 2, true},
		{"single collector failed", 1, 1, true},
		{"partial success", 2, 1, false},
		{"all succeeded", 3, 0, false},
		{"nothing enabled", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allCollectorsFailed(tt.enabled, tt.failed); got != tt.want {
				t.Errorf("allCollectorsFailed(%d, %d) = %v, want %v",
					tt.enabled, tt.failed, got, tt.want)
			}
		})
	}
}

// TestRunScan_EmptySuccessExitsZero drives runScan end-to-end with a
// config-only scan against an existing file that declares zero servers. The
// config collector succeeds with an empty graph, so runScan must return nil
// (exit 0) — a legitimately empty-but-successful result is not a failure.
func TestRunScan_EmptySuccessExitsZero(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "empty-ok.json")

	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "path", writeEmptyConfig(t))
	mustSetFlag(t, cmd, "scan-output", out)

	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("empty-but-successful scan must exit 0, got: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected artifact at %s: %v", out, err)
	}
}

// TestRunScan_AllCollectorsFailExitsNonZero drives runScan end-to-end into
// total failure: --config with an invalid effective project root makes the
// only enabled collector fail closed. runScan returns non-zero only AFTER
// writing the failed artifact so invalid discovery never looks complete-empty.
func TestRunScan_AllCollectorsFailExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "all-fail.json")

	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "project-dir", filepath.Join(dir, "no-such-project"))
	mustSetFlag(t, cmd, "scan-output", out)

	err := runScan(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "all 1 enabled collector(s) failed") {
		t.Fatalf("expected total-failure error, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("artifact must still be written on total failure: %v", statErr)
	}
	raw, readErr := os.ReadFile(out)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var artifact ingest.IngestData
	if decodeErr := json.Unmarshal(raw, &artifact); decodeErr != nil {
		t.Fatalf("decode failed artifact: %v", decodeErr)
	}
	root := ingest.CollectorRootCoverageKey("config")
	if ingest.CoverageStates(artifact.Meta.Collection)[root] != ingest.OutcomeFailed {
		t.Fatalf("invalid root coverage = %+v", artifact.Meta.Collection)
	}
	if len(ingest.CompleteAuthoritativeRoots(artifact.Meta.Collection)) != 0 {
		t.Fatalf("invalid root became authoritative: %+v", artifact.Meta.Collection.AuthoritativeRoots)
	}
}

func fingerprintTestEnvelope() *ingest.IngestData {
	key := ingest.CanonicalCoverageKey("scan", "network", "test")
	return &ingest.IngestData{Meta: ingest.IngestMeta{Collection: &ingest.CollectionReport{
		State: ingest.OutcomeComplete, CoverageKeys: []string{key},
	}}}
}

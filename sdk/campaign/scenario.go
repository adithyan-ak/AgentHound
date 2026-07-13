package campaign

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

// ErrNotRunnable marks a precondition failure that is distinct from an
// indeterminate probe outcome. The campaign CLI reports it and exits nonzero
// WITHOUT emitting evidence. Reject-hash-only and no-material are the canonical
// cases.
var ErrNotRunnable = errors.New("scenario not runnable")

// ProbeRequest is a single read attempt. An empty Credential is the unauth
// control probe; a non-empty Credential is the authed probe. The raw credential
// value is passed only in-process and must never be logged or serialized.
type ProbeRequest struct {
	Host        string
	ResourceURI string
	Credential  string
	Insecure    bool
	Timeout     time.Duration
}

// Unauthenticated reports whether this is the control probe.
func (r ProbeRequest) Unauthenticated() bool {
	return strings.TrimSpace(r.Credential) == ""
}

// ProbeResult is the classified result of a single read probe. Detail is a
// non-sensitive diagnostic string — it MUST NOT contain resource content or the
// credential value.
type ProbeResult struct {
	Status ProbeStatus
	Detail string
}

// Prober executes read-only probes against the exact predicted resource. It is
// an interface so scenarios can be exercised deterministically with a fake in
// tests, independent of any live MCP server.
type Prober interface {
	Probe(ctx context.Context, req ProbeRequest) ProbeResult
}

// RunInput carries everything a scenario needs. CredentialMaterial is supplied
// out of band (env/stdin) and is hash-matched locally; it is never logged or
// serialized into evidence.
type RunInput struct {
	Witness            Witness
	CredentialMaterial string
	Host               string
	EngagementID       string
	RunID              string
	Insecure           bool
	// Commit=false is the default dry-run: the scenario plans only and does not
	// probe or emit evidence.
	Commit  bool
	Timeout time.Duration
	// Prober overrides the scenario's default (real) prober. Tests set this.
	Prober Prober
	// Params carries scenario-specific knobs that are not part of the shared
	// differential-probe contract (the cred-reach scenario ignores it). The
	// reversible mcppoison round-trip scenario, for example, reads its target
	// tool id, injection content, write method/path, and list path from here.
	// It never carries credential material — that stays in CredentialMaterial.
	Params map[string]string
	// Now overrides the clock for deterministic verified_at values in tests.
	Now func() time.Time
}

// Clock returns the effective clock, defaulting to time.Now.
func (in RunInput) Clock() func() time.Time {
	if in.Now != nil {
		return in.Now
	}
	return time.Now
}

// RunResult is the scenario's outcome. On a dry run, Plan is populated and
// Evidence is nil. On commit, Outcome and Evidence are set; the caller builds
// the ingest graph from Evidence.EvidenceGraph so the envelope owns the scan ID
// and coverage tagging.
type RunResult struct {
	DryRun        bool
	Plan          string
	Outcome       Outcome
	Evidence      *Evidence
	ControlStatus ProbeStatus
	AuthedStatus  ProbeStatus
	// Roundtrip is set by STANDALONE target-mutation validation scenarios (the
	// reversible mcppoison round-trip) instead of the differential-probe fields
	// above. It reports the oracle and cleanup outcomes independently. It is nil
	// for the differential cred-reach scenario, which populates Outcome/Evidence.
	Roundtrip *RoundtripReport
}

// Scenario is a registered campaign scenario dispatched by ID from the campaign
// CLI's --scenario flag.
type Scenario interface {
	ID() string
	Version() int
	Description() string
	Run(ctx context.Context, in RunInput) (*RunResult, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Scenario{}
)

// Register adds a scenario to the collector-side registry. It panics on an empty
// or duplicate ID so registration bugs surface at init() time.
func Register(s Scenario) {
	if s == nil {
		panic("campaign: Register(nil)")
	}
	id := s.ID()
	if strings.TrimSpace(id) == "" {
		panic("campaign: scenario has empty ID")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[id]; exists {
		panic(fmt.Sprintf("campaign: scenario %q already registered", id))
	}
	registry[id] = s
}

// Get returns the registered scenario for id.
func Get(id string) (Scenario, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := registry[id]
	return s, ok
}

// List returns all registered scenarios sorted by ID.
func List() []Scenario {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Scenario, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// MatchCredentialMaterial hashes the out-of-band raw material with AgentHound's
// SHA-256 credential contract and requires an exact match to the witness
// value_hash. It never logs or returns the raw material. Missing material, a
// non-value_hash merge key, or a mismatch is a precondition failure
// (ErrNotRunnable), NOT an indeterminate outcome.
func MatchCredentialMaterial(w Witness, material string) error {
	if strings.TrimSpace(material) == "" {
		return fmt.Errorf(
			"%w: no executable credential material supplied "+
				"(hash-only credentials are not runnable)",
			ErrNotRunnable,
		)
	}
	if w.CredentialMergeKey != CredentialMergeKeyValueHash {
		return fmt.Errorf(
			"%w: credential merge_key %q has no observable raw material",
			ErrNotRunnable, w.CredentialMergeKey,
		)
	}
	if common.HashCredentialValue(material) != w.CredentialValueHash {
		return fmt.Errorf(
			"%w: supplied credential material does not match the exported value_hash",
			ErrNotRunnable,
		)
	}
	return nil
}

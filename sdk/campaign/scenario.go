package campaign

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
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

// ProbeStage identifies the last protocol stage reached by a probe.
type ProbeStage string

const (
	ProbeStageInitialize   ProbeStage = "initialize"
	ProbeStageResourceRead ProbeStage = "resource_read"
)

// Unauthenticated reports whether this is the control probe.
func (r ProbeRequest) Unauthenticated() bool {
	return strings.TrimSpace(r.Credential) == ""
}

// ProbeResult is the classified result of a single read probe. Stage records
// where the probe stopped. ResourceAddressed is true only after dispatching the
// exact requested resources/read operation. Detail is a bounded diagnostic code,
// never a target error, endpoint, resource content, or credential value.
type ProbeResult struct {
	Stage             ProbeStage
	ResourceAddressed bool
	Status            ProbeStatus
	Detail            string
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

// HTTPOrigin is the exact credential-forwarding boundary for an HTTP endpoint.
// It intentionally excludes path and query. Its fields are private so callers
// cannot accidentally serialize an origin derived from a potentially sensitive
// endpoint.
type HTTPOrigin struct {
	scheme   string
	hostname string
	port     string
}

// EndpointBinding is the validated, witness-bound endpoint used by a campaign.
// Endpoint preserves the untouched trimmed input for HTTP identity compatibility
// and live requests. TargetRef is safe for diagnostics because its query is
// removed. Neither value is part of witness or evidence serialization.
type EndpointBinding struct {
	Endpoint  string
	TargetRef string
	Origin    HTTPOrigin
}

var sensitiveQueryKeys = map[string]struct{}{
	"access_token":  {},
	"api-key":       {},
	"api_key":       {},
	"apikey":        {},
	"auth":          {},
	"authorization": {},
	"credential":    {},
	"key":           {},
	"password":      {},
	"secret":        {},
	"token":         {},
}

// BindEndpoint validates an operator-supplied HTTP(S) endpoint, applies
// best-effort known-secret query defenses, and binds the untouched trimmed
// representation to the exported server identity before any network operation.
//
// Arbitrary query bytes cannot be proven non-secret. Unknown query data remains
// identity-significant and is accepted, but the query is omitted from every
// returned diagnostic reference. Fixed known-sensitive decoded keys and decoded
// values exactly matching credentialMaterial are rejected as defense-in-depth.
func BindEndpoint(input, credentialMaterial, expectedServerID string) (EndpointBinding, error) {
	trimmed := strings.TrimSpace(input)
	u, origin, err := parseAbsoluteHTTPEndpoint(trimmed)
	if err != nil {
		return EndpointBinding{}, err
	}
	if queryContainsKnownSecret(u.RawQuery, credentialMaterial) {
		return EndpointBinding{}, fmt.Errorf("%w: endpoint query contains prohibited known-sensitive data", ErrNotRunnable)
	}
	actualServerID := ingest.ResolveMCPServerIdentity("http", trimmed).ObjectID
	if actualServerID != expectedServerID {
		return EndpointBinding{}, fmt.Errorf(
			"%w: endpoint identity does not match witness server_id", ErrNotRunnable,
		)
	}
	return EndpointBinding{
		Endpoint:  trimmed,
		TargetRef: redactedURL(u),
		Origin:    origin,
	}, nil
}

// ParseHTTPOrigin validates endpoint and returns its exact lowercased
// scheme+hostname+effective-port origin. It is shared by campaign and MCP
// transports so credential headers use one fail-closed policy.
func ParseHTTPOrigin(endpoint string) (HTTPOrigin, error) {
	_, origin, err := parseAbsoluteHTTPEndpoint(strings.TrimSpace(endpoint))
	return origin, err
}

// Matches reports whether u has the exact scheme, hostname, and effective port.
// Missing/malformed authority always fails closed.
func (o HTTPOrigin) Matches(u *url.URL) bool {
	if o.scheme == "" || o.hostname == "" || o.port == "" || u == nil {
		return false
	}
	candidate, err := originFromURL(u)
	if err != nil {
		return false
	}
	return o == candidate
}

// SanitizedTargetReference removes query data from a valid endpoint for CLI
// diagnostics. Invalid inputs return a fixed placeholder rather than echoing
// potentially sensitive bytes.
func SanitizedTargetReference(endpoint string) string {
	u, _, err := parseAbsoluteHTTPEndpoint(strings.TrimSpace(endpoint))
	if err != nil {
		return "<invalid-http-endpoint>"
	}
	return redactedURL(u)
}

func parseAbsoluteHTTPEndpoint(endpoint string) (*url.URL, HTTPOrigin, error) {
	if endpoint == "" {
		return nil, HTTPOrigin{}, fmt.Errorf("%w: HTTP endpoint is empty", ErrNotRunnable)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, HTTPOrigin{}, fmt.Errorf("%w: HTTP endpoint is malformed", ErrNotRunnable)
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, HTTPOrigin{}, fmt.Errorf("%w: endpoint must be absolute HTTP(S)", ErrNotRunnable)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, HTTPOrigin{}, fmt.Errorf("%w: HTTP endpoint requires a valid authority and hostname", ErrNotRunnable)
	}
	if u.User != nil {
		return nil, HTTPOrigin{}, fmt.Errorf("%w: endpoint userinfo is prohibited", ErrNotRunnable)
	}
	if u.Fragment != "" {
		return nil, HTTPOrigin{}, fmt.Errorf("%w: endpoint fragments are prohibited", ErrNotRunnable)
	}
	origin, err := originFromURL(u)
	if err != nil {
		return nil, HTTPOrigin{}, fmt.Errorf("%w: HTTP endpoint origin is malformed", ErrNotRunnable)
	}
	return u, origin, nil
}

func originFromURL(u *url.URL) (HTTPOrigin, error) {
	if u == nil || u.Host == "" || u.Hostname() == "" {
		return HTTPOrigin{}, errors.New("missing authority")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return HTTPOrigin{}, errors.New("unsupported scheme")
	}
	port := u.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return HTTPOrigin{
		scheme:   scheme,
		hostname: strings.ToLower(u.Hostname()),
		port:     port,
	}, nil
}

func queryContainsKnownSecret(rawQuery, credentialMaterial string) bool {
	if rawQuery == "" {
		return false
	}
	for _, field := range strings.Split(rawQuery, "&") {
		keyRaw, valueRaw, _ := strings.Cut(field, "=")
		key, keyErr := url.QueryUnescape(keyRaw)
		value, valueErr := url.QueryUnescape(valueRaw)
		if keyErr == nil {
			if _, denied := sensitiveQueryKeys[strings.ToLower(strings.TrimSpace(key))]; denied {
				return true
			}
		}
		if valueErr == nil && credentialMaterial != "" && value == credentialMaterial {
			return true
		}
	}
	return false
}

func redactedURL(u *url.URL) string {
	safe := *u
	safe.RawQuery = ""
	safe.ForceQuery = false
	return safe.String()
}

// RunResult is the scenario's outcome. On a dry run, Plan is populated and
// Evidence is nil. On commit, Outcome and Evidence are set; the caller builds
// the ingest graph from Evidence.EvidenceGraph so the envelope owns the scan ID
// and coverage tagging.
type RunResult struct {
	DryRun        bool
	Plan          string
	TargetRef     string
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

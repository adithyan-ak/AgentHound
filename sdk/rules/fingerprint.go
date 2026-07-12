package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FingerprintRule is the v0.2 shape for AI-service fingerprinting rules.
// It is a sibling of the v1 Rule type (which targets text-field matching
// inside the existing collectors): a fingerprint rule describes an HTTP
// probe sequence and a set of matchers that classify the response. When
// every required matcher passes, the rule emits one or more node kinds
// (multi-label per Section 3.5 of docs/plans/sprint3-offensive-primitives.md)
// plus a property bag.
//
// Fingerprint rules live under sdk/rules/builtin/fingerprints/*.yaml and
// are loaded by LoadFingerprints. They never appear in Engine.Rules() —
// the rules engine evaluates text only; fingerprints are HTTP-aware.
type FingerprintRule struct {
	ID          string             `yaml:"id"`
	Name        string             `yaml:"name"`
	Description string             `yaml:"description"`
	Version     int                `yaml:"version"`
	ServiceKind string             `yaml:"service_kind"`
	Probes      []FingerprintProbe `yaml:"probes"`
	Emit        FingerprintEmit    `yaml:"emit"`
	Source      string             `yaml:"-"`
}

// FingerprintProbe is one HTTP request and the matchers that classify its
// response. A rule may have multiple probes; ALL probes must succeed for
// the rule to match (conjunction). v0.2 only ships single-probe rules
// (Ollama: GET /api/version; LiteLLM: GET /health/liveliness); the
// multi-probe path exists for future fingerprinters that need stronger
// disambiguation.
type FingerprintProbe struct {
	Method   string             `yaml:"method"`
	Path     string             `yaml:"path"`
	Headers  map[string]string  `yaml:"headers,omitempty"`
	Matchers []FingerprintMatch `yaml:"matchers"`
	// CapturePath records a JSON-path expression whose extracted value
	// becomes a property on the emitted node. Used for the version
	// extraction in Ollama (capture $.version into properties.version).
	// Optional.
	Captures map[string]string `yaml:"captures,omitempty"`
}

// FingerprintMatch is a single conjunctive condition on the probe
// response. Type identifies which response field to check; the other
// fields configure the per-type comparison.
//
// Types:
//   - http_status: matches if response status code equals StatusCode
//     (or, if StatusRange != "", falls inside the range "2xx", "200-299").
//   - http_header: matches if response.Header.Get(Name) contains the
//     literal Value (case-insensitive if CaseInsensitive=true) OR
//     matches the regex Pattern when Pattern != "".
//   - body_equals: matches if the FULL response body (after trimming
//     trailing whitespace) equals Value exactly.
//   - body_contains: matches if the response body contains Value
//     (case-insensitive when CaseInsensitive=true).
//   - body_regex: matches if Pattern (a regex) finds at least one hit
//     in the response body.
//   - json_path: matches if extracting JSONPath at Path from the body
//     yields a value that satisfies the embedded comparison
//     (Equals/Regex/Exists). v0.2 supports a tiny JSONPath subset:
//     "$.field" and "$.field.subfield" only — no array indices, no
//     filters. Adequate for the v0.2 fingerprints; extend later as needed.
type FingerprintMatch struct {
	Type            string `yaml:"type"`
	StatusCode      int    `yaml:"status_code,omitempty"`
	StatusRange     string `yaml:"status_range,omitempty"`
	Name            string `yaml:"name,omitempty"`
	Value           string `yaml:"value,omitempty"`
	Pattern         string `yaml:"pattern,omitempty"`
	Path            string `yaml:"path,omitempty"`
	Equals          string `yaml:"equals,omitempty"`
	Regex           string `yaml:"regex,omitempty"`
	Exists          *bool  `yaml:"exists,omitempty"`
	CaseInsensitive bool   `yaml:"case_insensitive,omitempty"`
}

// FingerprintEmit declares the node kinds and properties produced when
// the rule matches. NodeKinds is multi-label: the first entry is the
// per-service primary label (e.g. "OllamaInstance") and subsequent
// entries are umbrella labels (typically just "AIService"). The writer
// MERGEs on the primary label and SETs the umbrellas (Phase 0
// semantics).
//
// Properties is a static template; values may reference the special
// "{capture:NAME}" placeholder which is replaced with the value the
// probe captured under that name. v0.2 keeps this simple — no
// recursive templating.
type FingerprintEmit struct {
	NodeKinds  []string          `yaml:"node_kinds"`
	Properties map[string]string `yaml:"properties,omitempty"`
}

// FingerprintResult is the outcome of running a single rule against a
// target. Matched is true only when every probe in the rule succeeded
// AND every matcher inside each probe matched. Captures collects
// values extracted by probe captures across all probes.
type FingerprintResult struct {
	Matched    bool
	RuleID     string
	NodeKinds  []string
	Properties map[string]string
	Captures   map[string]string
}

// LoadFingerprints reads YAML files from sdk/rules/builtin/fingerprints/
// and returns the parsed rules. The loader skips files that fail to
// parse (logging is the caller's job).
//
// v0.3+: when the process-global bundle override is set via
// SetBundleOverridePath (CLI --rules-bundle), bundle rules are merged
// over the embedded set with same-id rules from the bundle winning.
// See sdk/rules/bundle.go for the merge primitives.
func LoadFingerprints() ([]FingerprintRule, error) {
	override := getBundleOverridePath()
	fingerprintCacheMu.RLock()
	if fingerprintCacheInitialized && fingerprintCachePath == override {
		cached := append([]FingerprintRule(nil), fingerprintCacheRules...)
		err := fingerprintCacheErr
		fingerprintCacheMu.RUnlock()
		return cached, err
	}
	fingerprintCacheMu.RUnlock()

	loaded, failures, err := loadEffectiveFingerprints(override)
	fingerprintCacheMu.Lock()
	fingerprintCachePath = override
	fingerprintCacheInitialized = true
	fingerprintCacheRules = append([]FingerprintRule(nil), loaded...)
	fingerprintCacheFailures = append([]string(nil), failures...)
	fingerprintCacheErr = err
	fingerprintCacheMu.Unlock()
	return append([]FingerprintRule(nil), loaded...), err
}

func FingerprintLoadFailures() []string {
	fingerprintCacheMu.RLock()
	defer fingerprintCacheMu.RUnlock()
	return append([]string(nil), fingerprintCacheFailures...)
}

func loadEffectiveFingerprints(
	override string,
) ([]FingerprintRule, []string, error) {
	embedded, err := loadEmbeddedFingerprints()
	if err != nil {
		return nil, nil, err
	}
	if override == "" {
		return embedded, nil, nil
	}
	bundle, failures, err := loadFingerprintBundleWithFailures(override)
	if err != nil {
		// Bundle path was set but couldn't load — surface the error so
		// the operator notices, rather than silently falling back to the
		// embedded set (which would mask a bad bundle).
		return nil, failures, fmt.Errorf("load rules-bundle %q: %w", override, err)
	}
	return MergeFingerprintRules(embedded, bundle), sortedUniqueStrings(failures), nil
}

// loadEmbeddedFingerprints reads the binary-shipped fingerprint rules.
// Split from LoadFingerprints so the bundle override path can call
// it without recursing.
func loadEmbeddedFingerprints() ([]FingerprintRule, error) {
	const dir = "builtin/fingerprints"
	entries, err := fs.ReadDir(builtinFS, dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading fingerprints dir: %w", err)
	}
	var out []FingerprintRule
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := fs.ReadFile(builtinFS, filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var r FingerprintRule
		if err := yaml.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		r.Source = "builtin"
		if r.Version == 0 {
			r.Version = 2
		}
		out = append(out, r)
	}
	return out, nil
}

// ValidateFingerprint reports structural problems with a fingerprint rule.
// It runs at load time so a malformed rule is rejected before being
// dispatched. Returns nil if the rule is well-formed.
func ValidateFingerprint(r FingerprintRule) []ValidationError {
	var errs []ValidationError
	if !idPattern.MatchString(r.ID) {
		errs = append(errs, ValidationError{Field: "id", Message: "must be 3-64 chars, kebab-case"})
	}
	if r.Name == "" {
		errs = append(errs, ValidationError{Field: "name", Message: "must not be empty"})
	}
	if r.ServiceKind == "" {
		errs = append(errs, ValidationError{Field: "service_kind", Message: "must not be empty"})
	}
	if len(r.Probes) == 0 {
		errs = append(errs, ValidationError{Field: "probes", Message: "at least one probe required"})
	}
	for i, p := range r.Probes {
		if p.Method == "" {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("probes[%d].method", i), Message: "must not be empty"})
		}
		if p.Method != "GET" && p.Method != "HEAD" {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("probes[%d].method", i), Message: "v0.2 only supports GET / HEAD probes (looter contract is read-only)"})
		}
		if p.Path == "" {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("probes[%d].path", i), Message: "must not be empty"})
		}
		if len(p.Matchers) == 0 {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("probes[%d].matchers", i), Message: "at least one matcher required"})
		}
		for j, m := range p.Matchers {
			errs = append(errs, validateFingerprintMatcher(fmt.Sprintf("probes[%d].matchers[%d]", i, j), m)...)
		}
	}
	if len(r.Emit.NodeKinds) == 0 {
		errs = append(errs, ValidationError{Field: "emit.node_kinds", Message: "at least one node kind required"})
	}
	return errs
}

func validateFingerprintMatcher(prefix string, m FingerprintMatch) []ValidationError {
	var errs []ValidationError
	switch m.Type {
	case "http_status":
		if m.StatusCode == 0 && m.StatusRange == "" {
			errs = append(errs, ValidationError{Field: prefix, Message: "http_status requires status_code or status_range"})
		}
	case "http_header":
		if m.Name == "" {
			errs = append(errs, ValidationError{Field: prefix + ".name", Message: "http_header requires name"})
		}
		if m.Value == "" && m.Pattern == "" {
			errs = append(errs, ValidationError{Field: prefix, Message: "http_header requires value or pattern"})
		}
		if m.Pattern != "" {
			if _, err := regexp.Compile(m.Pattern); err != nil {
				errs = append(errs, ValidationError{Field: prefix + ".pattern", Message: fmt.Sprintf("invalid regex: %v", err)})
			}
		}
	case "body_equals", "body_contains":
		if m.Value == "" {
			errs = append(errs, ValidationError{Field: prefix + ".value", Message: m.Type + " requires non-empty value"})
		}
	case "body_regex":
		if m.Pattern == "" {
			errs = append(errs, ValidationError{Field: prefix + ".pattern", Message: "body_regex requires pattern"})
		} else if _, err := regexp.Compile(m.Pattern); err != nil {
			errs = append(errs, ValidationError{Field: prefix + ".pattern", Message: fmt.Sprintf("invalid regex: %v", err)})
		}
	case "json_path":
		if m.Path == "" {
			errs = append(errs, ValidationError{Field: prefix + ".path", Message: "json_path requires path"})
		}
		if m.Equals == "" && m.Regex == "" && m.Exists == nil {
			errs = append(errs, ValidationError{Field: prefix, Message: "json_path requires equals, regex, or exists"})
		}
		if m.Regex != "" {
			if _, err := regexp.Compile(m.Regex); err != nil {
				errs = append(errs, ValidationError{Field: prefix + ".regex", Message: fmt.Sprintf("invalid regex: %v", err)})
			}
		}
	default:
		errs = append(errs, ValidationError{Field: prefix + ".type", Message: fmt.Sprintf("unknown matcher type %q (want http_status/http_header/body_equals/body_contains/body_regex/json_path)", m.Type)})
	}
	return errs
}

// RunFingerprint executes the rule's probes against baseURL (e.g.
// "http://10.0.0.42:11434") and returns the result. The returned
// FingerprintResult.Matched is true only when every probe and every
// matcher succeeds. Network errors, non-OK status codes, and matcher
// mismatches all yield Matched=false (with a nil error in most cases —
// "this is not the expected service" is not a system error).
//
// Captures are accumulated across probes; later captures with the same
// name overwrite earlier ones. The Properties map on the result merges
// the rule's static properties (with {capture:NAME} placeholders
// resolved) and pre-existing captures.
//
// The HTTP client is supplied by the caller — tests inject httptest
// servers; real callers should use a *http.Client with a sane Timeout.
func RunFingerprint(ctx context.Context, client *http.Client, baseURL string, rule FingerprintRule) (*FingerprintResult, error) {
	if client == nil {
		return nil, errors.New("RunFingerprint: nil http client")
	}
	// Fingerprinter modules are registered during package init, before Cobra's
	// persistent pre-run resolves --rules-bundle. Resolve a same-ID override at
	// execution time from the cached effective set so the rule manifest and the
	// semantics actually run by the collector cannot drift.
	if rule.Source == BundleSourceBuiltin && getBundleOverridePath() != "" {
		effective, err := LoadFingerprints()
		if err != nil {
			return nil, err
		}
		for _, candidate := range effective {
			if candidate.ID != rule.ID {
				continue
			}
			if errs := ValidateFingerprint(candidate); len(errs) > 0 {
				return nil, fmt.Errorf("effective fingerprint rule %s invalid: %v", candidate.ID, errs)
			}
			rule = candidate
			break
		}
	}
	res := &FingerprintResult{
		RuleID:     rule.ID,
		NodeKinds:  rule.Emit.NodeKinds,
		Properties: map[string]string{},
		Captures:   map[string]string{},
	}
	for i, probe := range rule.Probes {
		ok, captures, err := runProbe(ctx, client, baseURL, probe)
		if err != nil {
			return res, fmt.Errorf("probe %d (%s %s): %w", i, probe.Method, probe.Path, err)
		}
		if !ok {
			return res, nil
		}
		for k, v := range captures {
			res.Captures[k] = v
		}
	}
	res.Matched = true
	res.Properties = resolveProperties(rule.Emit.Properties, res.Captures)
	return res, nil
}

// runProbe issues one HTTP request, applies its matchers, and returns
// (matched, captures, err). A non-nil err is reserved for unexpected
// runtime issues (request build failure, etc.) — a non-2xx status that
// fails the http_status matcher returns (false, nil, nil).
func runProbe(ctx context.Context, client *http.Client, baseURL string, probe FingerprintProbe) (bool, map[string]string, error) {
	// Concatenate baseURL and probe.Path with exactly one "/" between them.
	url := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(probe.Path, "/")

	req, err := http.NewRequestWithContext(ctx, probe.Method, url, nil)
	if err != nil {
		return false, nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range probe.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Network-level failures are normal for fingerprinting (closed
		// port, TLS handshake fail, etc.) — surface as no-match, not an
		// error, so the scanner can move on.
		return false, nil, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap body read at 1 MiB. Fingerprint targets like Ollama return
	// tiny JSON; an attacker-controlled large body shouldn't hang us.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, nil, nil
	}

	for _, m := range probe.Matchers {
		ok, err := evalFingerprintMatcher(m, resp, body)
		if err != nil {
			return false, nil, err
		}
		if !ok {
			return false, nil, nil
		}
	}

	captures := make(map[string]string)
	for name, path := range probe.Captures {
		if v, ok := jsonPathExtract(body, path); ok {
			captures[name] = v
		}
	}

	return true, captures, nil
}

func evalFingerprintMatcher(m FingerprintMatch, resp *http.Response, body []byte) (bool, error) {
	switch m.Type {
	case "http_status":
		if m.StatusCode != 0 {
			return resp.StatusCode == m.StatusCode, nil
		}
		// Status range "2xx" or "200-299"
		return statusInRange(resp.StatusCode, m.StatusRange), nil
	case "http_header":
		got := resp.Header.Get(m.Name)
		if m.Pattern != "" {
			re, err := regexp.Compile(m.Pattern)
			if err != nil {
				return false, fmt.Errorf("http_header pattern: %w", err)
			}
			return re.MatchString(got), nil
		}
		if m.CaseInsensitive {
			return strings.Contains(strings.ToLower(got), strings.ToLower(m.Value)), nil
		}
		return strings.Contains(got, m.Value), nil
	case "body_equals":
		return strings.TrimSpace(string(body)) == m.Value, nil
	case "body_contains":
		if m.CaseInsensitive {
			return strings.Contains(strings.ToLower(string(body)), strings.ToLower(m.Value)), nil
		}
		return strings.Contains(string(body), m.Value), nil
	case "body_regex":
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			return false, fmt.Errorf("body_regex pattern: %w", err)
		}
		return re.Match(body), nil
	case "json_path":
		v, exists := jsonPathExtract(body, m.Path)
		if m.Exists != nil {
			return exists == *m.Exists, nil
		}
		if !exists {
			return false, nil
		}
		if m.Equals != "" {
			return v == m.Equals, nil
		}
		if m.Regex != "" {
			re, err := regexp.Compile(m.Regex)
			if err != nil {
				return false, fmt.Errorf("json_path regex: %w", err)
			}
			return re.MatchString(v), nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("unknown matcher type %q", m.Type)
	}
}

// statusInRange parses a range string like "2xx", "200-299", or a single
// numeric "200" and reports whether code falls inside.
func statusInRange(code int, rangeStr string) bool {
	rangeStr = strings.TrimSpace(strings.ToLower(rangeStr))
	if rangeStr == "" {
		return false
	}
	// "2xx" / "3xx" form.
	if len(rangeStr) == 3 && strings.HasSuffix(rangeStr, "xx") {
		first, err := strconv.Atoi(rangeStr[:1])
		if err != nil {
			return false
		}
		return code >= first*100 && code < (first+1)*100
	}
	// "200-299" form.
	if dash := strings.IndexByte(rangeStr, '-'); dash > 0 {
		lo, err1 := strconv.Atoi(rangeStr[:dash])
		hi, err2 := strconv.Atoi(rangeStr[dash+1:])
		if err1 != nil || err2 != nil {
			return false
		}
		return code >= lo && code <= hi
	}
	// Single number form.
	if v, err := strconv.Atoi(rangeStr); err == nil {
		return code == v
	}
	return false
}

// jsonPathExtract extracts a value from JSON-encoded body at the
// supplied path. v0.2 supports a minimal subset:
//   - "$" → the whole body parsed as a JSON value, stringified
//   - "$.field"
//   - "$.field.subfield"
//
// Arrays and filter expressions are not supported. The returned value
// is stringified — numbers become their decimal string, bools become
// "true"/"false", strings are returned as-is, nested objects/arrays
// become their JSON encoding.
//
// Returns (stringified, true) when the path resolves; ("", false) if
// the body isn't valid JSON or the path does not exist.
func jsonPathExtract(body []byte, path string) (string, bool) {
	if !strings.HasPrefix(path, "$") {
		return "", false
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return "", false
	}
	if path == "$" {
		return stringifyJSONValue(v), true
	}
	rest := strings.TrimPrefix(path, "$.")
	if rest == path {
		// Path wasn't "$..." or "$"; malformed.
		return "", false
	}
	keys := strings.Split(rest, ".")
	cur := v
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = obj[k]
		if !ok {
			return "", false
		}
	}
	return stringifyJSONValue(cur), true
}

func stringifyJSONValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers — strip trailing zeroes for int-valued floats.
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	default:
		// Objects, arrays — re-encode.
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// resolveProperties expands {capture:NAME} placeholders in the rule's
// static property template. Unresolved placeholders are left as-is so
// the operator notices a misnamed capture.
func resolveProperties(template, captures map[string]string) map[string]string {
	out := make(map[string]string, len(template))
	for k, v := range template {
		if strings.Contains(v, "{capture:") {
			for cn, cv := range captures {
				v = strings.ReplaceAll(v, "{capture:"+cn+"}", cv)
			}
		}
		out[k] = v
	}
	for k, v := range captures {
		// Captures that don't appear in the template still surface as
		// properties so fingerprint authors can avoid duplicate template
		// entries for every captured field.
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// DefaultFingerprintHTTPClient builds the *http.Client fingerprinters use
// against AI-service targets. The timeout matches the scanner's per-host
// budget; redirects are blocked because every supported v0.2 service
// fingerprints on its own first-hop endpoint.
func DefaultFingerprintHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

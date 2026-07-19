package rules

type Rule struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Version     int         `yaml:"version"`
	Enabled     bool        `yaml:"enabled"`
	Scope       Scope       `yaml:"scope"`
	Severity    string      `yaml:"severity"`
	OWASP       []string    `yaml:"owasp"`
	Tags        []string    `yaml:"tags"`
	Matcher     MatcherSpec `yaml:"matcher"`
	Emit        EmitConfig  `yaml:"emit"`
	Tests       []TestCase  `yaml:"tests"`
	Source      string      `yaml:"-"`

	// ShadowExclude opts a rule out of the canonical instruction shadow pass so
	// it is evaluated against the raw text only. Structural charset-run
	// detectors (e.g. base64 payloads) set this because normalization and
	// letter-spacing collapse can synthesize long alphanumeric runs that never
	// existed in the source. Default (false) keeps injection rules on the
	// shadow.
	//
	// json:"-" keeps this field out of the semantic-digest payload so adding it
	// does not shift the digest of every unrelated text rule; its semantic
	// effect is captured instead by ruleUsesInstructionCanonicalization (a
	// shadow-excluded rule is no longer canonicalization-eligible, so the
	// canonicalizer version is not folded into its digest).
	ShadowExclude bool `yaml:"shadow_exclude,omitempty" json:"-"`
}

type Scope struct {
	Collector string   `yaml:"collector"`
	Targets   []string `yaml:"targets"`
}

type MatcherSpec struct {
	Type            string        `yaml:"type"`
	Pattern         string        `yaml:"pattern,omitempty"`
	Keywords        []string      `yaml:"keywords,omitempty"`
	Prefixes        []string      `yaml:"prefixes,omitempty"`
	CaseInsensitive bool          `yaml:"case_insensitive,omitempty"`
	WordBoundary    bool          `yaml:"word_boundary,omitempty"`
	MatchMode       string        `yaml:"match_mode,omitempty"`
	Operator        string        `yaml:"operator,omitempty"`
	Matchers        []MatcherSpec `yaml:"matchers,omitempty"`
	Charset         string        `yaml:"charset,omitempty"`
	Threshold       float64       `yaml:"threshold,omitempty"`
	MinLength       int           `yaml:"min_length,omitempty"`
}

type EmitConfig struct {
	FindingType   string   `yaml:"finding_type"`
	PropertyKey   string   `yaml:"property_key,omitempty"`
	PropertyValue any      `yaml:"property_value,omitempty"`
	Labels        []string `yaml:"labels,omitempty"`
}

type TestCase struct {
	Input       string `yaml:"input"`
	ShouldMatch bool   `yaml:"should_match"`
	Description string `yaml:"description"`
}

type Match struct {
	RuleID   string
	RuleName string
	Severity string
	Labels   []string
	Offset   int
	Text     string
	Emit     EmitConfig
}

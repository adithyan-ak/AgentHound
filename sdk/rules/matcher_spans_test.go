package rules

import (
	"reflect"
	"strings"
	"testing"
)

func TestMatcherSpansPreservePublicContract(t *testing.T) {
	matcher, err := compileMatcher(MatcherSpec{
		Type:    "regex",
		Pattern: `Z+`,
	})
	if err != nil {
		t.Fatal(err)
	}
	spans := matcher.matchSpans(strings.Repeat("Z", 150))
	if len(spans) != 1 ||
		spans[0].start != 0 ||
		spans[0].end != 150 {
		t.Fatalf("full spans = %+v", spans)
	}
	public := matcher.Match(strings.Repeat("Z", 150))
	if len(public) != 1 ||
		public[0].Offset != 0 ||
		len(public[0].Text) != 100 {
		t.Fatalf("public matches = %+v", public)
	}

	cases := []struct {
		name      string
		spec      MatcherSpec
		input     string
		wantSpans []matcherSpan
	}{
		{
			name: "keyword declaration order",
			spec: MatcherSpec{
				Type:      "keyword",
				Keywords:  []string{"alpha", "beta"},
				MatchMode: "all",
			},
			input:     "beta alpha",
			wantSpans: []matcherSpan{{start: 5, end: 10}, {start: 0, end: 4}},
		},
		{
			name: "prefix unicode lowercase mapping",
			spec: MatcherSpec{
				Type:            "prefix",
				Prefixes:        []string{"i"},
				CaseInsensitive: true,
			},
			input:     "İmpl",
			wantSpans: []matcherSpan{{start: 0, end: 2}},
		},
		{
			name: "compound or first child matches",
			spec: MatcherSpec{
				Type:     "compound",
				Operator: "or",
				Matchers: []MatcherSpec{
					{Type: "regex", Pattern: `foo`},
					{Type: "regex", Pattern: `bar`},
				},
			},
			input:     "foo bar",
			wantSpans: []matcherSpan{{start: 0, end: 3}},
		},
		{
			name: "compound and aggregates child spans in order",
			spec: MatcherSpec{
				Type:     "compound",
				Operator: "and",
				Matchers: []MatcherSpec{
					{Type: "regex", Pattern: `foo`},
					{Type: "regex", Pattern: `bar`},
				},
			},
			input:     "bar foo",
			wantSpans: []matcherSpan{{start: 4, end: 7}, {start: 0, end: 3}},
		},
		{
			name: "entropy spans full text",
			spec: MatcherSpec{
				Type:      "entropy",
				Charset:   "base64",
				Threshold: 3.0,
				MinLength: 8,
			},
			input:     "dGVzdDE2Y2hhcg==",
			wantSpans: []matcherSpan{{start: 0, end: 16}},
		},
		{
			name: "empty regex zero-length spans",
			spec: MatcherSpec{
				Type:    "regex",
				Pattern: ``,
			},
			input:     "ab",
			wantSpans: []matcherSpan{{start: 0, end: 0}, {start: 1, end: 1}, {start: 2, end: 2}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := compileMatcher(tc.spec)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			gotSpans := m.matchSpans(tc.input)
			if !reflect.DeepEqual(gotSpans, tc.wantSpans) {
				t.Fatalf("matchSpans = %+v, want %+v", gotSpans, tc.wantSpans)
			}
			gotPublic := m.Match(tc.input)
			if len(gotPublic) != len(tc.wantSpans) {
				t.Fatalf(
					"public len = %d, want %d",
					len(gotPublic),
					len(tc.wantSpans),
				)
			}
			for i, span := range tc.wantSpans {
				wantText := tc.input[span.start:span.end]
				if len(wantText) > 100 {
					wantText = wantText[:100]
				}
				if gotPublic[i].Offset != span.start ||
					gotPublic[i].Text != wantText {
					t.Fatalf(
						"public[%d] = {Offset:%d Text:%q}, want {Offset:%d Text:%q}",
						i,
						gotPublic[i].Offset,
						gotPublic[i].Text,
						span.start,
						wantText,
					)
				}
			}
		})
	}
}

func expectedRawMatches(
	engine *Engine,
	collector string,
	target string,
	text string,
) []Match {
	if len(text) > maxInputBytes {
		text = text[:maxInputBytes]
	}
	var candidates []compiledRule
	seen := make(map[string]bool)
	for _, key := range []string{
		collector + ":" + target,
		"all:" + target,
	} {
		for _, cr := range engine.byScope[key] {
			if seen[cr.rule.ID] {
				continue
			}
			seen[cr.rule.ID] = true
			candidates = append(candidates, cr)
		}
	}
	var matches []Match
	for _, cr := range candidates {
		for _, result := range cr.matcher.Match(text) {
			if !result.Matched {
				continue
			}
			matches = append(matches, Match{
				RuleID:   cr.rule.ID,
				RuleName: cr.rule.Name,
				Severity: cr.rule.Severity,
				Labels:   cr.rule.Emit.Labels,
				Offset:   result.Offset,
				Text:     result.Text,
				Emit:     cr.rule.Emit,
			})
		}
	}
	return matches
}

func TestEngineRawResultOrderContract(t *testing.T) {
	dir := t.TempDir()
	writeBenchmarkRule(t, dir, "order-config-regex.yaml", `
id: order-config-regex
name: Order config regex
version: 1
enabled: true
severity: high
scope:
  collector: config
  targets: [instruction.content]
matcher:
  type: regex
  pattern: 'ignore'
  case_insensitive: true
emit:
  finding_type: has_injection_patterns
`)
	writeBenchmarkRule(t, dir, "order-all-regex.yaml", `
id: order-all-regex
name: Order all regex
version: 1
enabled: true
severity: medium
scope:
  collector: all
  targets: [instruction.content]
matcher:
  type: regex
  pattern: 'secret'
emit:
  finding_type: has_secret
`)
	writeBenchmarkRule(t, dir, "order-config-keyword.yaml", `
id: order-config-keyword
name: Order config keyword
version: 1
enabled: true
severity: low
scope:
  collector: config
  targets: [instruction.content]
matcher:
  type: keyword
  keywords: [run, exec]
  match_mode: all
emit:
  finding_type: has_keyword
`)
	engine, err := NewEngine(LoadOptions{
		CustomDir: dir,
		EnableOnly: []string{
			"order-config-regex",
			"order-all-regex",
			"order-config-keyword",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	input := "ignore secret run exec ignore now"
	got := engine.Evaluate("config", "instruction.content", input)
	want := expectedRawMatches(engine, "config", "instruction.content", input)
	if len(got) == 0 {
		t.Fatal("expected raw matches, got none")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("raw result order/cardinality mismatch:\n got = %+v\nwant = %+v", got, want)
	}
}

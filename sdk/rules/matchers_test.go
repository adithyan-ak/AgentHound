package rules

import (
	"strings"
	"testing"
)

func TestRegexMatcher(t *testing.T) {
	tests := []struct {
		name    string
		spec    MatcherSpec
		input   string
		wantN   int
		wantErr bool
	}{
		{
			name:  "simple match",
			spec:  MatcherSpec{Type: "regex", Pattern: `</?IMPORTANT>`},
			input: "text <IMPORTANT>override</IMPORTANT> end",
			wantN: 2,
		},
		{
			name:  "case insensitive",
			spec:  MatcherSpec{Type: "regex", Pattern: `<important>`, CaseInsensitive: true},
			input: "<IMPORTANT>",
			wantN: 1,
		},
		{
			name:  "no match",
			spec:  MatcherSpec{Type: "regex", Pattern: `foobar`},
			input: "clean text",
			wantN: 0,
		},
		{
			name:    "invalid regex",
			spec:    MatcherSpec{Type: "regex", Pattern: `[invalid`},
			wantErr: true,
		},
		{
			name:  "already has case flag",
			spec:  MatcherSpec{Type: "regex", Pattern: `(?i)test`, CaseInsensitive: true},
			input: "TEST",
			wantN: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := compileMatcher(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			results := m.Match(tc.input)
			if len(results) != tc.wantN {
				t.Errorf("got %d results, want %d", len(results), tc.wantN)
			}
		})
	}
}

func TestRegexMatcherTextTruncation(t *testing.T) {
	spec := MatcherSpec{Type: "regex", Pattern: `A+`}
	m, err := compileMatcher(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	input := strings.Repeat("A", 200)
	results := m.Match(input)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if len(results[0].Text) != 100 {
		t.Errorf("text length = %d, want 100", len(results[0].Text))
	}
}

func TestKeywordMatcher(t *testing.T) {
	tests := []struct {
		name  string
		spec  MatcherSpec
		input string
		wantN int
	}{
		{
			name:  "any mode first match",
			spec:  MatcherSpec{Type: "keyword", Keywords: []string{"shell", "bash"}, CaseInsensitive: true, MatchMode: "any"},
			input: "run shell bash command",
			wantN: 1,
		},
		{
			name:  "all mode all present",
			spec:  MatcherSpec{Type: "keyword", Keywords: []string{"shell", "bash"}, CaseInsensitive: true, MatchMode: "all"},
			input: "shell and bash",
			wantN: 2,
		},
		{
			name:  "all mode missing one",
			spec:  MatcherSpec{Type: "keyword", Keywords: []string{"shell", "bash"}, CaseInsensitive: true, MatchMode: "all"},
			input: "only shell here",
			wantN: 0,
		},
		{
			name:  "case sensitive no match",
			spec:  MatcherSpec{Type: "keyword", Keywords: []string{"Shell"}, CaseInsensitive: false},
			input: "shell command",
			wantN: 0,
		},
		{
			name:  "case sensitive match",
			spec:  MatcherSpec{Type: "keyword", Keywords: []string{"Shell"}, CaseInsensitive: false},
			input: "Shell command",
			wantN: 1,
		},
		{
			name:  "no keywords no match",
			spec:  MatcherSpec{Type: "keyword", Keywords: []string{}, CaseInsensitive: true},
			input: "anything",
			wantN: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := compileMatcher(tc.spec)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			results := m.Match(tc.input)
			if len(results) != tc.wantN {
				t.Errorf("got %d results, want %d", len(results), tc.wantN)
			}
		})
	}
}

func TestCompoundMatcher(t *testing.T) {
	tests := []struct {
		name  string
		spec  MatcherSpec
		input string
		wantN int
	}{
		{
			name: "and both match",
			spec: MatcherSpec{
				Type:     "compound",
				Operator: "and",
				Matchers: []MatcherSpec{
					{Type: "keyword", Keywords: []string{"postgres"}, CaseInsensitive: true},
					{Type: "keyword", Keywords: []string{"prod"}, CaseInsensitive: true},
				},
			},
			input: "postgres://prod-db",
			wantN: 2,
		},
		{
			name: "and one missing",
			spec: MatcherSpec{
				Type:     "compound",
				Operator: "and",
				Matchers: []MatcherSpec{
					{Type: "keyword", Keywords: []string{"postgres"}, CaseInsensitive: true},
					{Type: "keyword", Keywords: []string{"prod"}, CaseInsensitive: true},
				},
			},
			input: "postgres://dev-db",
			wantN: 0,
		},
		{
			name: "or first matches",
			spec: MatcherSpec{
				Type:     "compound",
				Operator: "or",
				Matchers: []MatcherSpec{
					{Type: "keyword", Keywords: []string{"alpha"}, CaseInsensitive: true},
					{Type: "keyword", Keywords: []string{"beta"}, CaseInsensitive: true},
				},
			},
			input: "alpha version",
			wantN: 1,
		},
		{
			name: "or none matches",
			spec: MatcherSpec{
				Type:     "compound",
				Operator: "or",
				Matchers: []MatcherSpec{
					{Type: "keyword", Keywords: []string{"alpha"}, CaseInsensitive: true},
					{Type: "keyword", Keywords: []string{"beta"}, CaseInsensitive: true},
				},
			},
			input: "gamma version",
			wantN: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := compileMatcher(tc.spec)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			results := m.Match(tc.input)
			if len(results) != tc.wantN {
				t.Errorf("got %d results, want %d", len(results), tc.wantN)
			}
		})
	}
}

func TestEntropyMatcher(t *testing.T) {
	tests := []struct {
		name  string
		spec  MatcherSpec
		input string
		wantN int
	}{
		{
			name:  "high entropy base64",
			spec:  MatcherSpec{Type: "entropy", Charset: "base64", Threshold: 4.5, MinLength: 8},
			input: "sk+ant+abc123XYZdefGHIjklMNOpqrSTUvwx",
			wantN: 1,
		},
		{
			name:  "low entropy base64",
			spec:  MatcherSpec{Type: "entropy", Charset: "base64", Threshold: 4.5, MinLength: 8},
			input: "aaaaaaaa",
			wantN: 0,
		},
		{
			name:  "too short",
			spec:  MatcherSpec{Type: "entropy", Charset: "base64", Threshold: 4.5, MinLength: 8},
			input: "abc",
			wantN: 0,
		},
		{
			name:  "non base64 chars rejected",
			spec:  MatcherSpec{Type: "entropy", Charset: "base64", Threshold: 4.5, MinLength: 8},
			input: "hello world with spaces",
			wantN: 0,
		},
		{
			name:  "high entropy hex",
			spec:  MatcherSpec{Type: "entropy", Charset: "hex", Threshold: 3.0, MinLength: 8},
			input: "a1b2c3d4e5f6a7b8",
			wantN: 1,
		},
		{
			name:  "hex with non-hex chars rejected",
			spec:  MatcherSpec{Type: "entropy", Charset: "hex", Threshold: 3.0, MinLength: 8},
			input: "a1b2c3g4",
			wantN: 0,
		},
		{
			name:  "empty string",
			spec:  MatcherSpec{Type: "entropy", Charset: "base64", Threshold: 4.5, MinLength: 8},
			input: "",
			wantN: 0,
		},
		{
			name:  "base64 with padding",
			spec:  MatcherSpec{Type: "entropy", Charset: "base64", Threshold: 3.0, MinLength: 8},
			input: "dGVzdDE2Y2hhcg==",
			wantN: 1,
		},
		{
			name:  "hex charset rejects base64 plus sign",
			spec:  MatcherSpec{Type: "entropy", Charset: "hex", Threshold: 3.0, MinLength: 8},
			input: "a1b2c3d4+5f6",
			wantN: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := compileMatcher(tc.spec)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			results := m.Match(tc.input)
			if len(results) != tc.wantN {
				t.Errorf("got %d results, want %d", len(results), tc.wantN)
			}
		})
	}
}

func TestPrefixMatcher(t *testing.T) {
	tests := []struct {
		name  string
		spec  MatcherSpec
		input string
		wantN int
	}{
		{
			name:  "matching prefix",
			spec:  MatcherSpec{Type: "prefix", Prefixes: []string{"sk-ant-"}},
			input: "sk-ant-abc123",
			wantN: 1,
		},
		{
			name:  "no matching prefix",
			spec:  MatcherSpec{Type: "prefix", Prefixes: []string{"sk-ant-"}},
			input: "sk-abc123",
			wantN: 0,
		},
		{
			name:  "case insensitive",
			spec:  MatcherSpec{Type: "prefix", Prefixes: []string{"vault://"}, CaseInsensitive: true},
			input: "VAULT://secret/path",
			wantN: 1,
		},
		{
			name:  "case sensitive no match",
			spec:  MatcherSpec{Type: "prefix", Prefixes: []string{"sk-ant-"}, CaseInsensitive: false},
			input: "SK-ANT-abc123",
			wantN: 0,
		},
		{
			name:  "multiple prefixes first wins",
			spec:  MatcherSpec{Type: "prefix", Prefixes: []string{"ghp_", "gho_", "sk-"}},
			input: "gho_abcdef",
			wantN: 1,
		},
		{
			name:  "empty input",
			spec:  MatcherSpec{Type: "prefix", Prefixes: []string{"sk-"}},
			input: "",
			wantN: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := compileMatcher(tc.spec)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			results := m.Match(tc.input)
			if len(results) != tc.wantN {
				t.Errorf("got %d results, want %d", len(results), tc.wantN)
			}
			if tc.wantN > 0 && results[0].Offset != 0 {
				t.Errorf("prefix offset = %d, want 0", results[0].Offset)
			}
		})
	}
}

// TestKeywordMatcherUnicodeFolds guards against the offset corruption /
// slice-bounds panic that arises when strings.ToLower changes byte length:
// expanding folds ('Ⱥ' U+023A, 2 bytes → 'ⱥ' U+2C65, 3 bytes) grow the lowered
// string so the lowered match index runs past the original's length (the old
// code's `text[idx:idx+len(kw)]` panicked with slice-bounds-out-of-range);
// shrinking folds ('İ' U+0130, 2 bytes → "i", 1 byte) produce a smaller
// lowered string and previously yielded garbled evidence. The reported
// offset/text must be a valid byte span into the ORIGINAL text in both cases.
func TestKeywordMatcherUnicodeFolds(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantText  string
		wantStart int
	}{
		{
			name:     "expanding fold before match does not panic",
			input:    "Ⱥshell", // 'Ⱥ' grows under ToLower; old code panicked here
			wantText: "shell",
		},
		{
			name:     "multiple expanding folds before match",
			input:    "ⰊⱥⰋⱥshell", // mixed expanders pile up the byte-length skew
			wantText: "shell",
		},
		{
			name:      "shrinking fold before match yields correct evidence",
			input:     "İsecret",
			wantText:  "secret",
			wantStart: 2, // 'İ' is 2 bytes in the original
		},
		{
			name:     "expanding folds surrounding match",
			input:    "ȺshellȾ",
			wantText: "shell",
		},
		{
			name:     "uppercase match preserves original casing in evidence",
			input:    "SHELL here",
			wantText: "SHELL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kw := "shell"
			if tc.name == "shrinking fold before match yields correct evidence" {
				kw = "secret"
			}
			spec := MatcherSpec{Type: "keyword", Keywords: []string{kw}, CaseInsensitive: true}
			m, err := compileMatcher(spec)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			results := m.Match(tc.input) // must not panic
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			r := results[0]
			if r.Offset < 0 || r.Offset+len(r.Text) > len(tc.input) {
				t.Fatalf("offset/text out of bounds: offset=%d text=%q len(input)=%d", r.Offset, r.Text, len(tc.input))
			}
			if r.Text != tc.wantText {
				t.Errorf("evidence text = %q, want %q", r.Text, tc.wantText)
			}
			if tc.wantStart != 0 && r.Offset != tc.wantStart {
				t.Errorf("offset = %d, want %d", r.Offset, tc.wantStart)
			}
		})
	}
}

// TestPrefixMatcherUnicodeFolds is the prefix-matcher equivalent of the
// keyword fold guard: a case-insensitive prefix match over a prefix that
// folds with a different byte length must report a valid in-bounds evidence
// span into the original text and must not panic.
func TestPrefixMatcherUnicodeFolds(t *testing.T) {
	// 'İ' (U+0130, 2 bytes) lowercases to "i" (1 byte) — a shrinking fold.
	// The prefix "i" matched case-insensitively against "İmpl" must produce a
	// valid evidence span (the original 'İ', 2 bytes), not a 1-byte slice that
	// would split the rune or report the wrong text.
	spec := MatcherSpec{Type: "prefix", Prefixes: []string{"i"}, CaseInsensitive: true}
	m, err := compileMatcher(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	input := "İmpl"
	results := m.Match(input) // must not panic
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Offset != 0 {
		t.Errorf("prefix offset = %d, want 0", r.Offset)
	}
	if r.Offset+len(r.Text) > len(input) {
		t.Fatalf("evidence out of bounds: text=%q len(input)=%d", r.Text, len(input))
	}
	if r.Text != "İ" {
		t.Errorf("evidence text = %q, want %q", r.Text, "İ")
	}

	// Expanding fold: prefix "ⱭⱭ" (the chars themselves are the prefix) — just
	// assert no panic and a valid span for an ASCII prefix preceding nothing.
	spec2 := MatcherSpec{Type: "prefix", Prefixes: []string{"vault://"}, CaseInsensitive: true}
	m2, err := compileMatcher(spec2)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	in2 := "VAULT://secret"
	res2 := m2.Match(in2)
	if len(res2) != 1 {
		t.Fatalf("got %d results, want 1", len(res2))
	}
	if res2[0].Text != "VAULT://" {
		t.Errorf("evidence text = %q, want %q", res2[0].Text, "VAULT://")
	}
}

func TestUnknownMatcherType(t *testing.T) {
	_, err := compileMatcher(MatcherSpec{Type: "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown matcher type")
	}
}

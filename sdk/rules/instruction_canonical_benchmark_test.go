package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBenchmarkRule(
	tb testing.TB,
	dir string,
	filename string,
	content string,
) {
	tb.Helper()
	if err := os.WriteFile(
		filepath.Join(dir, filename),
		[]byte(content),
		0o644,
	); err != nil {
		tb.Fatal(err)
	}
}

func benchmarkInstructionEngine(
	b *testing.B,
	id string,
	pattern string,
) *Engine {
	b.Helper()
	dir := b.TempDir()
	rule := fmt.Sprintf(`
id: %s
name: Canonical benchmark
version: 1
enabled: true
severity: high
scope:
  collector: config
  targets: [instruction.content]
matcher:
  type: regex
  pattern: %q
  case_insensitive: true
emit:
  finding_type: has_injection_patterns
`, id, pattern)
	writeBenchmarkRule(b, dir, id+".yaml", rule)
	engine, err := NewEngine(LoadOptions{
		CustomDir:  dir,
		EnableOnly: []string{id},
	})
	if err != nil {
		b.Fatal(err)
	}
	return engine
}

func alternatingCanonicalInput(size int) string {
	unit := "Ａ\u200B"
	return strings.Repeat(unit, size/len(unit)) +
		strings.Repeat("x", size%len(unit))
}

func BenchmarkEngineEvaluateInstruction(b *testing.B) {
	engine := benchmarkInstructionEngine(
		b,
		"canonical-benchmark-phrase",
		`\bignore\s+previous\s+instructions\b`,
	)
	rawMarker := " ignore previous instructions"
	raw := strings.Repeat("a", maxInputBytes-len(rawMarker)) + rawMarker
	shadowMarker := " ｉｇｎｏｒｅ\u200B previous instructions"
	prefix := alternatingCanonicalInput(maxInputBytes - len(shadowMarker))
	adversarial := prefix + shadowMarker
	if len(raw) != maxInputBytes || len(adversarial) != maxInputBytes {
		b.Fatalf("input lengths raw=%d adversarial=%d", len(raw), len(adversarial))
	}
	cases := []struct {
		name  string
		input string
	}{
		{name: "raw_1MiB", input: raw},
		{name: "canonical_adversarial_1MiB", input: adversarial},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = engine.Evaluate("config", "instruction.content", tc.input)
			}
		})
	}
}

func BenchmarkEngineEvaluateInstructionHighCardinality(b *testing.B) {
	patterns := []struct {
		name    string
		id      string
		pattern string
	}{
		{name: "dot", id: "canonical-benchmark-dot", pattern: `.`},
		{name: "empty", id: "canonical-benchmark-empty", pattern: ``},
	}
	sizes := []int{64 << 10, 128 << 10, 256 << 10}
	for _, pattern := range patterns {
		engine := benchmarkInstructionEngine(
			b,
			pattern.id,
			pattern.pattern,
		)
		for _, size := range sizes {
			input := alternatingCanonicalInput(size)
			name := fmt.Sprintf("%s_%d", pattern.name, size)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_ = engine.Evaluate(
						"config",
						"instruction.content",
						input,
					)
				}
			})
		}
	}
}

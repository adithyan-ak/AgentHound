package instruction

import (
	"encoding/json"
	"strings"
	"testing"
)

func validSignal() Signal {
	return Signal{
		RuleID: "instruction-ignore-previous", Label: "Ignore Previous Instructions",
		Severity: "critical", Strength: StrengthPrimary,
		RawOffset: 8, Line: 2, Column: 1, Match: "Ignore previous instructions",
		ContextBefore: "first line\n", ContextAfter: "\nand continue",
	}
}

func TestParseEvidenceJSONStrictContract(t *testing.T) {
	valid := Evidence{
		Version: EvidenceVersion, Verdict: VerdictSignal,
		TotalSignals: 1, Signals: []Signal{validSignal()},
	}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEvidenceJSON(string(encoded))
	if err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	if parsed.Signals[0].Match != valid.Signals[0].Match {
		t.Fatalf("match = %q", parsed.Signals[0].Match)
	}

	tests := map[string]string{
		"unknown field":         strings.TrimSuffix(string(encoded), "}") + `,"extra":true}`,
		"trailing value":        string(encoded) + `{}`,
		"unsupported version":   strings.Replace(string(encoded), `"version":1`, `"version":2`, 1),
		"invalid verdict":       strings.Replace(string(encoded), `"verdict":"signal"`, `"verdict":"maybe"`, 1),
		"invalid strength":      strings.Replace(string(encoded), `"strength":"primary"`, `"strength":"weak"`, 1),
		"zero-based line":       strings.Replace(string(encoded), `"line":2`, `"line":0`, 1),
		"count mismatch":        strings.Replace(string(encoded), `"total_signals":1`, `"total_signals":0`, 1),
		"truncation mismatch":   strings.Replace(string(encoded), `"truncated":false`, `"truncated":true`, 1),
		"null retained signals": strings.Replace(string(encoded), `"signals":[`, `"signals":null,"discarded":[`, 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEvidenceJSON(raw); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestMarshalBoundedCapsCountAndBytes(t *testing.T) {
	signals := make([]Signal, 40)
	for index := range signals {
		signals[index] = validSignal()
		signals[index].RuleID += string(rune('a' + index))
		signals[index].RawOffset = index
		signals[index].ContextAfter = strings.Repeat(
			"x",
			MaxEvidenceWindowSize-len(signals[index].ContextBefore)-len(signals[index].Match),
		)
	}
	evidence, raw, err := MarshalBounded(VerdictPoisoning, signals)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.TotalSignals != 40 || !evidence.Truncated {
		t.Fatalf("bounds metadata = %+v", evidence)
	}
	if len(evidence.Signals) > MaxSignals || len(raw) > MaxEvidenceBytes {
		t.Fatalf("retained=%d bytes=%d", len(evidence.Signals), len(raw))
	}
	if _, err := ParseEvidenceJSON(raw); err != nil {
		t.Fatalf("bounded evidence rejected: %v", err)
	}
}

func TestMarshalBoundedWithTotalPreservesUnrenderedCount(t *testing.T) {
	signals := []Signal{validSignal(), validSignal()}
	signals[1].RuleID = "second-rule"
	evidence, raw, err := MarshalBoundedWithTotal(VerdictPoisoning, signals, 80_000)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.TotalSignals != 80_000 || !evidence.Truncated || len(evidence.Signals) != 2 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if _, err := ParseEvidenceJSON(raw); err != nil {
		t.Fatalf("encoded evidence rejected: %v", err)
	}
	if _, _, err := MarshalBoundedWithTotal(VerdictSignal, signals, 1); err == nil {
		t.Fatal("accepted total smaller than retained count")
	}
}

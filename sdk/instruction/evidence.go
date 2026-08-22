package instruction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	EvidenceVersion       = 1
	MaxSignals            = 32
	MaxEvidenceBytes      = 64 << 10
	MaxEvidenceWindowSize = 2 << 10
)

type Verdict string

const (
	VerdictClean     Verdict = "clean"
	VerdictSignal    Verdict = "signal"
	VerdictPoisoning Verdict = "poisoning"
)

type Scope string

const (
	ScopeExactProject Scope = "exact_project"
	ScopeExactUser    Scope = "exact_user"
	ScopeDeep         Scope = "deep"
)

type Strength string

const (
	StrengthDecisive   Strength = "decisive"
	StrengthPrimary    Strength = "primary"
	StrengthSupporting Strength = "supporting"
)

type Signal struct {
	RuleID         string   `json:"rule_id"`
	Label          string   `json:"label"`
	Severity       string   `json:"severity"`
	Strength       Strength `json:"strength"`
	RawOffset      int      `json:"raw_offset"`
	Line           int      `json:"line"`
	Column         int      `json:"column"`
	Match          string   `json:"match"`
	ContextBefore  string   `json:"context_before"`
	ContextAfter   string   `json:"context_after"`
	DecodedExcerpt string   `json:"decoded_excerpt,omitempty"`
}

type Evidence struct {
	Version      int      `json:"version"`
	Verdict      Verdict  `json:"verdict"`
	TotalSignals int      `json:"total_signals"`
	Truncated    bool     `json:"truncated"`
	Signals      []Signal `json:"signals"`
}

func ValidVerdict(value Verdict) bool {
	switch value {
	case VerdictClean, VerdictSignal, VerdictPoisoning:
		return true
	default:
		return false
	}
}

func ValidScope(value Scope) bool {
	switch value {
	case ScopeExactProject, ScopeExactUser, ScopeDeep:
		return true
	default:
		return false
	}
}

func ParseEvidenceJSON(raw string) (Evidence, error) {
	if len(raw) == 0 {
		return Evidence{}, fmt.Errorf("must not be empty")
	}
	if len(raw) > MaxEvidenceBytes {
		return Evidence{}, fmt.Errorf("exceeds %d byte limit", MaxEvidenceBytes)
	}
	var evidence Evidence
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, fmt.Errorf("decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Evidence{}, fmt.Errorf("multiple JSON values are not allowed")
		}
		return Evidence{}, fmt.Errorf("trailing JSON: %w", err)
	}
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

func (e Evidence) Validate() error {
	if e.Version != EvidenceVersion {
		return fmt.Errorf("version must be %d", EvidenceVersion)
	}
	if !ValidVerdict(e.Verdict) {
		return fmt.Errorf("invalid verdict %q", e.Verdict)
	}
	if e.Signals == nil {
		return fmt.Errorf("signals must be a non-null array")
	}
	if len(e.Signals) > MaxSignals {
		return fmt.Errorf("signals exceeds %d item limit", MaxSignals)
	}
	if e.TotalSignals < 0 || e.TotalSignals < len(e.Signals) {
		return fmt.Errorf("total_signals must be at least the retained signal count")
	}
	if e.Truncated != (e.TotalSignals > len(e.Signals)) {
		return fmt.Errorf("truncated must reflect omitted signals")
	}
	if e.Verdict == VerdictClean && e.TotalSignals != 0 {
		return fmt.Errorf("clean evidence cannot contain signals")
	}
	if e.Verdict != VerdictClean && e.TotalSignals == 0 {
		return fmt.Errorf("non-clean evidence requires a signal")
	}
	for index, signal := range e.Signals {
		if err := signal.Validate(); err != nil {
			return fmt.Errorf("signals[%d]: %w", index, err)
		}
	}
	return nil
}

func (s Signal) Validate() error {
	if strings.TrimSpace(s.RuleID) == "" {
		return fmt.Errorf("rule_id must not be empty")
	}
	if strings.TrimSpace(s.Label) == "" {
		return fmt.Errorf("label must not be empty")
	}
	switch s.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("invalid severity %q", s.Severity)
	}
	switch s.Strength {
	case StrengthDecisive, StrengthPrimary, StrengthSupporting:
	default:
		return fmt.Errorf("invalid strength %q", s.Strength)
	}
	if s.RawOffset < 0 {
		return fmt.Errorf("raw_offset must be non-negative")
	}
	if s.Line < 1 || s.Column < 1 {
		return fmt.Errorf("line and column must be one-based")
	}
	if s.Match == "" {
		return fmt.Errorf("match must not be empty")
	}
	windowBytes := len(s.ContextBefore) + len(s.Match) + len(s.ContextAfter)
	if windowBytes > MaxEvidenceWindowSize {
		return fmt.Errorf("evidence window exceeds %d byte limit", MaxEvidenceWindowSize)
	}
	if len(s.DecodedExcerpt) > MaxEvidenceWindowSize {
		return fmt.Errorf("decoded_excerpt exceeds %d byte limit", MaxEvidenceWindowSize)
	}
	return nil
}

// MarshalBounded keeps the highest-priority signals that fit the public
// artifact contract. The caller supplies signals in deterministic priority
// order and the envelope records every omitted signal.
func MarshalBounded(verdict Verdict, signals []Signal) (Evidence, string, error) {
	return MarshalBoundedWithTotal(verdict, signals, len(signals))
}

// MarshalBoundedWithTotal keeps the supplied highest-priority signals while
// recording the total number of validated signals observed by the caller. It
// is used when producing every signal would itself defeat the evidence bound.
func MarshalBoundedWithTotal(verdict Verdict, signals []Signal, total int) (Evidence, string, error) {
	if total < len(signals) {
		return Evidence{}, "", fmt.Errorf("total signal count %d is smaller than retained count %d", total, len(signals))
	}
	if total > MaxSignals {
		if len(signals) > MaxSignals {
			signals = signals[:MaxSignals]
		}
	}
	retained := make([]Signal, len(signals))
	copy(retained, signals)
	for {
		evidence := Evidence{
			Version:      EvidenceVersion,
			Verdict:      verdict,
			TotalSignals: total,
			Truncated:    total > len(retained),
			Signals:      retained,
		}
		encoded, err := json.Marshal(evidence)
		if err != nil {
			return Evidence{}, "", err
		}
		if len(encoded) <= MaxEvidenceBytes {
			if err := evidence.Validate(); err != nil {
				return Evidence{}, "", err
			}
			return evidence, string(encoded), nil
		}
		if len(retained) == 0 {
			return Evidence{}, "", fmt.Errorf("instruction evidence envelope exceeds %d bytes", MaxEvidenceBytes)
		}
		retained = retained[:len(retained)-1]
	}
}

func DecodeJSONBytes(raw []byte) (Evidence, error) {
	return ParseEvidenceJSON(string(bytes.TrimSpace(raw)))
}

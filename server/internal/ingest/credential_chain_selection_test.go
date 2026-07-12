package ingest

import (
	"context"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

// TestChainEligibleGeneration is the F2 counterexample for participation
// gating: a loot OR config-bearing generation qualifies to anchor a credential
// chain ONLY with explicit (complete/partial) coverage; a failed/unknown-
// coverage loot or config artifact makes no positive claim and must be
// excluded, and mcp/a2a/network generations never qualify regardless of
// coverage.
func TestChainEligibleGeneration(t *testing.T) {
	cases := []struct {
		name string
		scan model.Scan
		want bool
	}{
		{"loot complete", model.Scan{Scope: "loot:litellm", Collector: "scan", CoverageStatus: sdkingest.StatusComplete}, true},
		{"loot partial", model.Scan{Scope: "loot:ollama", Collector: "scan", CoverageStatus: sdkingest.StatusPartial}, true},
		{"loot unknown excluded", model.Scan{Scope: "loot:litellm", Collector: "scan", CoverageStatus: sdkingest.StatusUnknown}, false},
		{"loot failed excluded", model.Scan{Scope: "loot:litellm", Collector: "scan", CoverageStatus: sdkingest.StatusFailed}, false},
		{"config complete", model.Scan{Scope: "config", Collector: "config", CoverageStatus: sdkingest.StatusComplete}, true},
		{"config partial", model.Scan{Scope: "config", Collector: "config", CoverageStatus: sdkingest.StatusPartial}, true},
		{"config unknown excluded", model.Scan{Scope: "config", Collector: "config", CoverageStatus: sdkingest.StatusUnknown}, false},
		{"config failed excluded", model.Scan{Scope: "config", Collector: "config", CoverageStatus: sdkingest.StatusFailed}, false},
		{"scan:local complete included", model.Scan{Scope: scopeScanLocal, Collector: "scan", CoverageStatus: sdkingest.StatusComplete}, true},
		{"scan:network excluded", model.Scan{Scope: scopeScanNetwork, Collector: "scan", CoverageStatus: sdkingest.StatusComplete}, false},
		{"mcp excluded", model.Scan{Scope: "mcp", Collector: "mcp", CoverageStatus: sdkingest.StatusComplete}, false},
		{"a2a excluded", model.Scan{Scope: "a2a", Collector: "a2a", CoverageStatus: sdkingest.StatusComplete}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := chainEligibleGeneration(tc.scan); got != tc.want {
				t.Errorf("chainEligibleGeneration(%+v) = %v, want %v", tc.scan, got, tc.want)
			}
		})
	}
}

// TestOwnerEligibleForCredentialChain is the counterexample for OWNER gating:
// the artifact currently being ingested runs the chain only when it is itself
// an explicit config-bearing generation or a complete/partial loot generation.
// An unrelated network sweep or an mcp/a2a-only re-ingest never runs the chain,
// and a failed/unknown-coverage loot/config owner is excluded too.
func TestOwnerEligibleForCredentialChain(t *testing.T) {
	cases := []struct {
		name      string
		scope     string
		collector string
		coverage  sdkingest.CollectionStatus
		want      bool
	}{
		{"config complete", "config", "config", sdkingest.StatusComplete, true},
		{"config partial", "config", "config", sdkingest.StatusPartial, true},
		{"config unknown excluded", "config", "config", sdkingest.StatusUnknown, false},
		{"loot complete", "loot:litellm", "scan", sdkingest.StatusComplete, true},
		{"loot partial", "loot:litellm", "scan", sdkingest.StatusPartial, true},
		{"loot unknown excluded", "loot:litellm", "scan", sdkingest.StatusUnknown, false},
		{"loot failed excluded", "loot:litellm", "scan", sdkingest.StatusFailed, false},
		{"scan:local complete", scopeScanLocal, "scan", sdkingest.StatusComplete, true},
		{"network sweep excluded", scopeScanNetwork, "scan", sdkingest.StatusComplete, false},
		{"mcp-only excluded", "mcp", "mcp", sdkingest.StatusComplete, false},
		{"a2a-only excluded", "a2a", "a2a", sdkingest.StatusComplete, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownerEligibleForCredentialChain(tc.scope, tc.collector, tc.coverage); got != tc.want {
				t.Errorf("ownerEligibleForCredentialChain(%q,%q,%q) = %v, want %v",
					tc.scope, tc.collector, tc.coverage, got, tc.want)
			}
		})
	}
}

// TestSelectCredentialChainGenerations is the F2 counterexample for
// owner-specific, superseded-exclusion selection: the owner's OWN scope is
// excluded (its new generation supersedes any promoted same-scope generation),
// and only eligible participants of OTHER scopes are joined across.
func TestSelectCredentialChainGenerations(t *testing.T) {
	store := &fakeScanStore{current: map[string]*model.Scan{
		// Owner scope — must be excluded so a superseded same-scope loot
		// generation is never mixed with the new owner generation.
		"loot:litellm": {GenerationID: "gen-owner-scope", Scope: "loot:litellm", Collector: "scan", CoverageStatus: sdkingest.StatusComplete},
		// Eligible other-scope participants (explicit coverage).
		"loot:ollama":  {GenerationID: "gen-loot-ollama", Scope: "loot:ollama", Collector: "scan", CoverageStatus: sdkingest.StatusPartial},
		"config":       {GenerationID: "gen-config", Scope: "config", Collector: "config", CoverageStatus: sdkingest.StatusComplete},
		scopeScanLocal: {GenerationID: "gen-scanlocal", Scope: scopeScanLocal, Collector: "scan", CoverageStatus: sdkingest.StatusComplete},
		// Ineligible: unknown-coverage config, unknown-coverage loot, network
		// sweep, mcp.
		"config-unknown": {GenerationID: "gen-config-unknown", Scope: "config-unknown", Collector: "config", CoverageStatus: sdkingest.StatusUnknown},
		"loot:vllm":      {GenerationID: "gen-loot-unknown", Scope: "loot:vllm", Collector: "scan", CoverageStatus: sdkingest.StatusUnknown},
		scopeScanNetwork: {GenerationID: "gen-network", Scope: scopeScanNetwork, Collector: "scan", CoverageStatus: sdkingest.StatusComplete},
		"mcp":            {GenerationID: "gen-mcp", Scope: "mcp", Collector: "mcp", CoverageStatus: sdkingest.StatusComplete},
	}}
	p := &Pipeline{scanStore: store}

	got, err := p.selectCredentialChainGenerations(context.Background(), "loot:litellm")
	if err != nil {
		t.Fatalf("selectCredentialChainGenerations: %v", err)
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	want := []string{"gen-loot-ollama", "gen-config", "gen-scanlocal"}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("expected %q in selected generations, got %v", w, got)
		}
	}
	excluded := []string{"gen-owner-scope", "gen-config-unknown", "gen-loot-unknown", "gen-network", "gen-mcp"}
	for _, x := range excluded {
		if gotSet[x] {
			t.Errorf("did not expect %q in selected generations, got %v", x, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("selected %d generations, want %d: %v", len(got), len(want), got)
	}
}

// TestSelectCredentialChainGenerationsPropagatesError is the selection-store
// error counterexample at the helper level: a failed CurrentGenerations read is
// RETURNED, not swallowed, so the pipeline can fail post-processing and gate
// promotion rather than silently join against an incomplete generation set.
func TestSelectCredentialChainGenerationsPropagatesError(t *testing.T) {
	store := &fakeScanStore{currentGensErr: errContextSel("selection store down")}
	p := &Pipeline{scanStore: store}
	gens, err := p.selectCredentialChainGenerations(context.Background(), "loot:litellm")
	if err == nil {
		t.Fatal("expected the CurrentGenerations error to propagate")
	}
	if gens != nil {
		t.Errorf("expected nil generations on error, got %v", gens)
	}
}

type errContextSel string

func (e errContextSel) Error() string { return string(e) }

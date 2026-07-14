// Package credreach implements the v1 differential credential-reach campaign
// scenario. It is READ-ONLY: it reads the exact predicted MCP resource once
// without authentication (control) and once with the hash-matched credential
// (authed), then classifies the pair per the differential outcome matrix. It
// mutates nothing on the target, so it needs no receipts or rollback.
//
// The scenario self-registers under ID "cred-reach". The collector binary
// blank-imports this package (collector/cmd/agenthound/main.go) so `agenthound
// campaign --scenario cred-reach` can dispatch it.
package credreach

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

const (
	scenarioID      = "cred-reach"
	scenarioVersion = 1
)

// Scenario is the differential credential-reach oracle.
type Scenario struct{}

func init() { campaign.Register(&Scenario{}) }

func (s *Scenario) ID() string   { return scenarioID }
func (s *Scenario) Version() int { return scenarioVersion }
func (s *Scenario) Description() string {
	return "Differential credential-reach verification (read-only): unauth control " +
		"probe vs. hash-matched authed probe of the exact predicted MCP resource."
}

// Run executes the scenario. Precondition failures (invalid witness, no/mismatched
// credential material) return an error; MatchCredentialMaterial wraps
// campaign.ErrNotRunnable so the CLI can distinguish not-runnable from an
// indeterminate outcome. Dry runs plan only and never probe.
func (s *Scenario) Run(ctx context.Context, in campaign.RunInput) (*campaign.RunResult, error) {
	if err := in.Witness.Validate(); err != nil {
		return nil, fmt.Errorf("witness invalid: %w", err)
	}
	// Precondition: require executable material that hash-matches the exported
	// value_hash. Hash-only / no-material credentials are not runnable.
	if err := campaign.MatchCredentialMaterial(in.Witness, in.CredentialMaterial); err != nil {
		return nil, err
	}
	binding, err := campaign.BindEndpoint(in.Host, in.CredentialMaterial, in.Witness.ServerID)
	if err != nil {
		return nil, err
	}

	if !in.Commit {
		return &campaign.RunResult{
			DryRun:    true,
			Plan:      planText(in, binding.TargetRef),
			TargetRef: binding.TargetRef,
		}, nil
	}

	prober := in.Prober
	if prober == nil {
		prober = defaultProber()
	}

	control := prober.Probe(ctx, campaign.ProbeRequest{
		Host:        binding.Endpoint,
		ResourceURI: in.Witness.ResourceURI,
		Credential:  "",
		Insecure:    in.Insecure,
		Timeout:     in.Timeout,
	})
	authed := prober.Probe(ctx, campaign.ProbeRequest{
		Host:        binding.Endpoint,
		ResourceURI: in.Witness.ResourceURI,
		Credential:  in.CredentialMaterial,
		Insecure:    in.Insecure,
		Timeout:     in.Timeout,
	})

	outcome := campaign.Classify(control, authed)

	runID := strings.TrimSpace(in.RunID)
	if runID == "" {
		runID = uuid.NewString()
	}

	evidence := &campaign.Evidence{
		ScenarioID:      scenarioID,
		ScenarioVersion: scenarioVersion,
		RunID:           runID,
		EngagementID:    in.EngagementID,
		OracleType:      campaign.OracleTypeDifferentialCredentialReach,
		Outcome:         outcome,
		ControlStatus:   control.Status,
		AuthedStatus:    authed.Status,
		VerifiedAt:      in.Clock()().UTC().Format(time.RFC3339),
		Witness:         in.Witness,
	}

	return &campaign.RunResult{
		Outcome:       outcome,
		Evidence:      evidence,
		TargetRef:     binding.TargetRef,
		ControlStatus: control.Status,
		AuthedStatus:  authed.Status,
	}, nil
}

// planText renders the read-only plan for a dry run. It names the exact probes
// without revealing the credential material.
func planText(in campaign.RunInput, targetRef string) string {
	w := in.Witness
	var b strings.Builder
	fmt.Fprintf(&b, "scenario:      %s (v%d)\n", scenarioID, scenarioVersion)
	fmt.Fprintf(&b, "oracle:        %s\n", campaign.OracleTypeDifferentialCredentialReach)
	fmt.Fprintf(&b, "target:        %s\n", targetRef)
	fmt.Fprintf(&b, "server node:   %s\n", w.ServerID)
	fmt.Fprintf(&b, "resource node: %s\n", w.ResourceID)
	fmt.Fprintf(&b, "resource uri:  %s\n", w.ResourceURI)
	fmt.Fprintf(&b, "credential:    %s (value_hash matched out-of-band)\n", w.CredentialID)
	b.WriteString("plan (READ-ONLY, no mutation):\n")
	b.WriteString("  1. resources/read the exact resource WITHOUT authentication (control)\n")
	b.WriteString("  2. resources/read the exact resource WITH the hash-matched credential (authed)\n")
	b.WriteString("  3. classify differentially and emit graph evidence\n")
	return b.String()
}

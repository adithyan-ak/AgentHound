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
	binding, err := campaign.BindEndpoint(in.Host, in.CredentialMaterial, in.Witness.ServerIdentityID)
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

	runID := strings.TrimSpace(in.RunID)
	if runID == "" {
		runID = uuid.NewString()
	}
	elapsedLimit := in.Timeout
	if elapsedLimit <= 0 {
		elapsedLimit = defaultProbeTimeout
	}
	runCtx, cancel, budget := campaign.NewBudgetContext(ctx, campaign.RunLimits{
		RequestLimit:  16,
		MutationLimit: 0,
		ElapsedLimit:  elapsedLimit,
	})
	defer cancel()
	now := in.Clock()
	runStarted := now().UTC()
	report := &campaign.RunReport{
		ReportVersion:       campaign.RunReportVersion,
		ScenarioID:          scenarioID,
		ScenarioVersion:     scenarioVersion,
		CampaignRunID:       runID,
		EngagementID:        in.EngagementID,
		AgentID:             in.Witness.AgentID,
		ServerID:            in.Witness.ServerID,
		CredentialID:        in.Witness.CredentialID,
		ResourceID:          in.Witness.ResourceID,
		TargetRef:           binding.TargetRef,
		EvidenceFingerprint: in.Witness.Fingerprint(),
		StartedAt:           runStarted.Format(time.RFC3339Nano),
		Steps:               []campaign.StepObservation{},
		Cleanup: campaign.CleanupReport{
			Status: campaign.CleanupNotApplicable, Postcondition: "not_applicable",
			ReceiptRetained: false,
		},
	}
	report.AddStepAt(
		campaign.StepValidateBind,
		campaign.OperationValidation,
		"bound",
		runStarted,
		now(),
	)

	prober := in.Prober
	if prober == nil {
		prober = defaultProber()
	}

	controlStarted := now()
	control := prober.Probe(runCtx, campaign.ProbeRequest{
		Host:        binding.Endpoint,
		ResourceURI: in.Witness.ResourceIdentityInput,
		Credential:  "",
		Insecure:    in.Insecure,
		Timeout:     in.Timeout,
	})
	report.AddStepAt(
		campaign.StepControlProbe,
		campaign.OperationNetworkRead,
		probeObservation(control),
		controlStarted,
		now(),
	)
	authed := campaign.ProbeResult{}
	if budget.Exhaustion(runCtx) == nil {
		authedStarted := now()
		authed = prober.Probe(runCtx, campaign.ProbeRequest{
			Host:        binding.Endpoint,
			ResourceURI: in.Witness.ResourceIdentityInput,
			Credential:  in.CredentialMaterial,
			Insecure:    in.Insecure,
			Timeout:     in.Timeout,
		})
		report.AddStepAt(
			campaign.StepAuthenticatedProbe,
			campaign.OperationNetworkRead,
			probeObservation(authed),
			authedStarted,
			now(),
		)
	} else {
		stepTime := now()
		report.AddStepAt(
			campaign.StepAuthenticatedProbe,
			campaign.OperationNetworkRead,
			"budget_exhausted",
			stepTime,
			stepTime,
		)
	}

	classifyStarted := now()
	outcome := campaign.Classify(control, authed)
	report.AddStepAt(
		campaign.StepClassify,
		campaign.OperationDecision,
		string(outcome),
		classifyStarted,
		now(),
	)

	emitStarted := now()
	evidence := &campaign.Evidence{
		ScenarioID:       scenarioID,
		ScenarioVersion:  scenarioVersion,
		RunID:            runID,
		EngagementID:     in.EngagementID,
		OracleType:       campaign.OracleTypeDifferentialCredentialReach,
		Outcome:          outcome,
		ControlStage:     control.Stage,
		ControlStatus:    control.Status,
		ControlAddressed: control.ResourceAddressed,
		AuthedStage:      authed.Stage,
		AuthedStatus:     authed.Status,
		AuthedAddressed:  authed.ResourceAddressed,
		VerifiedAt:       now().UTC().Format(time.RFC3339),
		Witness:          in.Witness,
	}

	report.AddStepAt(
		campaign.StepEmit,
		campaign.OperationEvidenceEmission,
		evidenceObservation(outcome),
		emitStarted,
		now(),
	)
	report.Oracle = campaign.OracleReport{
		Type:        campaign.OracleTypeDifferentialCredentialReach,
		Observation: probePairObservation(control, authed),
		Outcome:     string(outcome),
	}
	report.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	report.Budget = budget.Snapshot()
	result := &campaign.RunResult{
		Outcome:       outcome,
		Evidence:      evidence,
		TargetRef:     binding.TargetRef,
		ControlStatus: control.Status,
		AuthedStatus:  authed.Status,
		Report:        report,
	}
	if exhausted := budget.Exhaustion(runCtx); exhausted != nil {
		return result, exhausted
	}
	return result, nil
}

func probeObservation(result campaign.ProbeResult) string {
	if result.Detail != "" {
		return result.Detail
	}
	if result.Stage == "" || result.Status == "" {
		return "incomplete"
	}
	return string(result.Stage) + "_" + string(result.Status)
}

func probePairObservation(control, authed campaign.ProbeResult) string {
	if control.Stage == "" || authed.Stage == "" {
		return "incomplete"
	}
	return "staged_pair"
}

func evidenceObservation(outcome campaign.Outcome) string {
	if _, emitted := outcome.EdgeKind(); emitted {
		return "evidence_emitted"
	}
	return "no_evidence"
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
	fmt.Fprintf(&b, "resource uri:  %s\n", w.ResourceIdentityInput)
	fmt.Fprintf(&b, "credential:    %s (value_hash matched out-of-band)\n", w.CredentialID)
	b.WriteString("plan (READ-ONLY, no mutation):\n")
	b.WriteString("  1. resources/read the exact resource WITHOUT authentication (control)\n")
	b.WriteString("  2. resources/read the exact resource WITH the hash-matched credential (authed)\n")
	b.WriteString("  3. classify differentially and emit graph evidence\n")
	return b.String()
}

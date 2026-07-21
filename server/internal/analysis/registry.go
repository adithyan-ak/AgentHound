package analysis

import "github.com/adithyan-ak/agenthound/server/internal/analysis/processors"

func allProcessors() []PostProcessor {
	return []PostProcessor{
		// auth_strength is a pre-pass: it materializes paired effective node
		// authentication plus effective TRUSTS_SERVER assessment properties.
		// No deps; must run before any processor that reads those values.
		&processors.AuthStrength{},
		&processors.HasAccessTo{},
		&processors.CanExecute{},
		&processors.Shadows{},
		&processors.PoisonedDescription{},
		&processors.PoisonedInstructions{},
		// taints runs before can_reach so its cross-tool taint edges can
		// influence the transitive reachability walk.
		&processors.Taints{},
		&processors.CanReach{},
		// CrossServiceCredentialChain depends on can_reach and emits
		// CAN_REACH edges that span Config Collector + LiteLLM Looter
		// emissions joined on Credential.value_hash. See
		// cross_service_credential_chain.go for the full path
		// description; design rationale in
		// docs/plans/sprint3-offensive-primitives.md 3.7 + 4.5.
		&processors.CrossServiceCredentialChain{},
		// ifc_violation reads HAS_ACCESS_TO paths populated earlier and the
		// raw INGESTS_UNTRUSTED edges; runs after the credential chain,
		// before the exfiltration detector.
		&processors.IfcViolation{},
		&processors.CanExfiltrate{},
		&processors.CanImpersonate{},
		&processors.ConfusedDeputy{},
		&processors.CrossProtocol{},
		&processors.RiskScore{},
	}
}

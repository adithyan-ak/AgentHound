package analysis

import "github.com/adithyan-ak/agenthound/server/internal/analysis/processors"

func allProcessors() []PostProcessor {
	return []PostProcessor{
		&processors.HasAccessTo{},
		&processors.CanExecute{},
		&processors.Shadows{},
		&processors.PoisonedDescription{},
		&processors.PoisonedInstructions{},
		&processors.CanReach{},
		&processors.CanExfiltrate{},
		&processors.CanImpersonate{},
		&processors.CrossProtocol{},
		&processors.RiskScore{},
	}
}

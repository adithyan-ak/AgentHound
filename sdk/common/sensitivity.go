package common

type SensitivityLevel string

const (
	SensitivityUnknown  SensitivityLevel = "unknown"
	SensitivityCritical SensitivityLevel = "critical"
	SensitivityHigh     SensitivityLevel = "high"
	SensitivityMedium   SensitivityLevel = "medium"
	SensitivityLow      SensitivityLevel = "low"
	SensitivityNone     SensitivityLevel = "none"
)

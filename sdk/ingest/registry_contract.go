package ingest

import "strings"

const (
	InstructionRegistryGeneration = 1
	InstructionRegistryDigest     = "sha256:773fcf9a5c1dd003edc2f631c55258f701e7b1dbd9a2add59b16905efa214e9b"

	InstructionMethodExactUser    = "instruction_exact_user"
	InstructionMethodExactProject = "instruction_exact_project"
	InstructionMethodDeep         = "instruction_deep"
	InstructionMethodSource       = "instruction_source"
)

type InstructionCoverageMode string

const (
	InstructionCoverageExactUser    InstructionCoverageMode = "exact_user"
	InstructionCoverageExactProject InstructionCoverageMode = "exact_project"
	InstructionCoverageDeep         InstructionCoverageMode = "deep"
)

type RegistryContract struct {
	Generation int    `json:"generation"`
	Digest     string `json:"digest"`
}

func CurrentInstructionRegistryContract() RegistryContract {
	return RegistryContract{
		Generation: InstructionRegistryGeneration,
		Digest:     InstructionRegistryDigest,
	}
}

func (c RegistryContract) Equal(other RegistryContract) bool {
	return c.Generation == other.Generation &&
		c.Digest == other.Digest
}

func InstructionCoverageModeForMethod(method string) (InstructionCoverageMode, bool) {
	switch method {
	case InstructionMethodExactUser:
		return InstructionCoverageExactUser, true
	case InstructionMethodExactProject:
		return InstructionCoverageExactProject, true
	case InstructionMethodDeep:
		return InstructionCoverageDeep, true
	default:
		return "", false
	}
}

func IsInstructionCoverageState(state OutcomeState) bool {
	switch state {
	case OutcomeComplete, OutcomeTruncated, OutcomePartial, OutcomeFailed:
		return true
	default:
		return false
	}
}

func InstructionRootMatchesMethod(rootKey, method string) bool {
	mode, ok := InstructionCoverageModeForMethod(method)
	if !ok {
		return false
	}
	expectedKind := ""
	switch mode {
	case InstructionCoverageExactUser:
		expectedKind = "instruction-exact-user"
	case InstructionCoverageExactProject:
		expectedKind = "instruction-exact-project"
	case InstructionCoverageDeep:
		expectedKind = "instruction-deep"
	}
	return strings.HasPrefix(rootKey, "config:"+expectedKind+":sha256:")
}

func cloneRegistryContract(contract *RegistryContract) *RegistryContract {
	if contract == nil {
		return nil
	}
	cloned := *contract
	return &cloned
}

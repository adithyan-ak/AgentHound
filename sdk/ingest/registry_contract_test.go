package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCurrentInstructionRegistryContractIsStableAndValid(t *testing.T) {
	contract := CurrentInstructionRegistryContract()
	if contract.Generation != 3 {
		t.Fatalf("generation = %d, want selected-project partition generation 3", contract.Generation)
	}
	if contract.Generation != InstructionRegistryGeneration {
		t.Fatalf("generation = %d, want %d", contract.Generation, InstructionRegistryGeneration)
	}
	if contract.Digest != InstructionRegistryDigest {
		t.Fatalf("digest = %q, want %q", contract.Digest, InstructionRegistryDigest)
	}
	if !strings.HasPrefix(contract.Digest, "sha256:") || len(contract.Digest) != len("sha256:")+64 {
		t.Fatalf("digest = %q, want sha256:<64 lowercase hex>", contract.Digest)
	}
}

func TestCoverageRootRegistryContractJSON(t *testing.T) {
	contract := CurrentInstructionRegistryContract()
	root := CoverageRoot{
		CoverageKey:       CanonicalCoverageKey("config", "instruction-deep", "/home/example"),
		ChildCoverageKeys: []string{},
		RegistryContract:  &contract,
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"registry_contract"`) {
		t.Fatalf("encoded root = %s, want registry contract", encoded)
	}

	root.RegistryContract = nil
	encoded, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"registry_contract"`) {
		t.Fatalf("encoded non-instruction root = %s, want omitted registry contract", encoded)
	}
}

func TestInstructionRootMethodContract(t *testing.T) {
	tests := []struct {
		method string
		kind   string
		mode   InstructionCoverageMode
	}{
		{InstructionMethodExactUser, "instruction-exact-user", InstructionCoverageExactUser},
		{InstructionMethodExactProject, "instruction-exact-project", InstructionCoverageExactProject},
		{InstructionMethodDeep, "instruction-deep", InstructionCoverageDeep},
	}
	for _, test := range tests {
		key := CanonicalCoverageKey("config", test.kind, "/scope")
		if !InstructionRootMatchesMethod(key, test.method) {
			t.Errorf("%q did not match %q", key, test.method)
		}
		mode, ok := InstructionCoverageModeForMethod(test.method)
		if !ok || mode != test.mode {
			t.Errorf("mode for %q = %q, %v; want %q, true", test.method, mode, ok, test.mode)
		}
	}
}

package campaign

import (
	"context"
	"testing"
)

type stubScenario struct{ id string }

func (s stubScenario) ID() string          { return s.id }
func (s stubScenario) Version() int        { return 1 }
func (s stubScenario) Description() string { return "stub" }
func (s stubScenario) Run(_ context.Context, _ RunInput) (*RunResult, error) {
	return &RunResult{}, nil
}

func TestRegistryRegisterGetList(t *testing.T) {
	// Registration mutates package state; use unique IDs to stay isolated.
	Register(stubScenario{id: "zeta-scenario"})
	Register(stubScenario{id: "alpha-scenario"})

	if _, ok := Get("zeta-scenario"); !ok {
		t.Fatal("registered scenario not found")
	}
	if _, ok := Get("missing-scenario"); ok {
		t.Fatal("unregistered scenario should not be found")
	}

	list := List()
	// List is sorted; alpha must precede zeta among our two registrations.
	var alphaIdx, zetaIdx = -1, -1
	for i, s := range list {
		switch s.ID() {
		case "alpha-scenario":
			alphaIdx = i
		case "zeta-scenario":
			zetaIdx = i
		}
	}
	if alphaIdx == -1 || zetaIdx == -1 || alphaIdx > zetaIdx {
		t.Fatalf("List not sorted: alpha=%d zeta=%d", alphaIdx, zetaIdx)
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	Register(stubScenario{id: "dup-scenario"})
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration must panic")
		}
	}()
	Register(stubScenario{id: "dup-scenario"})
}

func TestRegistryEmptyIDPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("empty ID must panic")
		}
	}()
	Register(stubScenario{id: ""})
}

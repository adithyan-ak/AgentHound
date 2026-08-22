package module

import (
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

// fakeModule is a minimal Module for registry tests. Tests rely on real
// ID/Action/Target shapes only; nothing is implemented beyond identity.
type fakeModule struct {
	id     string
	action action.Action
	target string
}

func (f *fakeModule) ID() string            { return f.id }
func (f *fakeModule) Action() action.Action { return f.action }
func (f *fakeModule) Target() string        { return f.target }
func (f *fakeModule) Description() string   { return "fake module for tests" }
func (f *fakeModule) Version() string       { return "0.0.0" }
func (f *fakeModule) IsDestructive() bool   { return false }

// resetRegistry clears the package-global registry so tests do not leak
// state into each other. The registry is small and tests run with -race;
// taking the write lock once per reset is fine.
func resetRegistry() {
	registryMu.Lock()
	registry = map[string]Module{}
	registryMu.Unlock()
}

func TestRegisterAndGet(t *testing.T) {
	resetRegistry()
	m := &fakeModule{id: "test.enumerate", action: action.Enumerate, target: "test"}
	Register(m)

	got, ok := Get("test.enumerate")
	if !ok {
		t.Fatal("Get returned !ok for registered module")
	}
	if got != m {
		t.Errorf("Get returned %v, want %v", got, m)
	}

	if _, ok := Get("does.not.exist"); ok {
		t.Error("Get returned ok for unregistered ID")
	}
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	resetRegistry()
	a := &fakeModule{id: "dup.id", action: action.Enumerate, target: "x"}
	b := &fakeModule{id: "dup.id", action: action.Collect, target: "y"}
	Register(a)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate Register, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "dup.id") {
			t.Errorf("panic message %q does not mention conflicting ID", msg)
		}
	}()
	Register(b)
}

func TestRegisterPanicsOnNil(t *testing.T) {
	resetRegistry()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil module")
		}
	}()
	Register(nil)
}

func TestRegisterPanicsOnEmptyID(t *testing.T) {
	resetRegistry()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty ID")
		}
	}()
	Register(&fakeModule{id: "", action: action.Enumerate, target: "x"})
}

func TestList(t *testing.T) {
	resetRegistry()
	Register(&fakeModule{id: "z.last", action: action.Enumerate, target: "z"})
	Register(&fakeModule{id: "a.first", action: action.Collect, target: "a"})
	Register(&fakeModule{id: "m.middle", action: action.Enumerate, target: "m"})

	all := List()
	if len(all) != 3 {
		t.Fatalf("List returned %d, want 3", len(all))
	}
	wantOrder := []string{"a.first", "m.middle", "z.last"}
	for i, m := range all {
		if m.ID() != wantOrder[i] {
			t.Errorf("List()[%d] = %q, want %q", i, m.ID(), wantOrder[i])
		}
	}
}

func TestListByAction(t *testing.T) {
	resetRegistry()
	Register(&fakeModule{id: "mcp.enumerate", action: action.Enumerate, target: "mcp"})
	Register(&fakeModule{id: "a2a.enumerate", action: action.Enumerate, target: "a2a"})
	Register(&fakeModule{id: "litellm.loot", action: action.Collect, target: "litellm"})

	enums := ListByAction(action.Enumerate)
	if len(enums) != 2 {
		t.Fatalf("ListByAction(Enumerate) returned %d, want 2", len(enums))
	}
	if enums[0].ID() != "a2a.enumerate" || enums[1].ID() != "mcp.enumerate" {
		t.Errorf("ListByAction not sorted: got %q,%q", enums[0].ID(), enums[1].ID())
	}

	loots := ListByAction(action.Collect)
	if len(loots) != 1 || loots[0].ID() != "litellm.loot" {
		t.Errorf("ListByAction(Loot) = %v, want [litellm.loot]", loots)
	}

	none := ListByAction(action.Poison)
	if len(none) != 0 {
		t.Errorf("ListByAction(Poison) = %v, want empty", none)
	}
}

func TestGetByTarget(t *testing.T) {
	resetRegistry()
	Register(&fakeModule{id: "mcp.enumerate", action: action.Enumerate, target: "mcp"})
	Register(&fakeModule{id: "litellm.loot", action: action.Collect, target: "litellm"})

	m, ok := GetByTarget("litellm", action.Collect)
	if !ok {
		t.Fatal("GetByTarget(litellm, Loot) returned !ok")
	}
	if m.ID() != "litellm.loot" {
		t.Errorf("GetByTarget = %q, want litellm.loot", m.ID())
	}

	if _, ok := GetByTarget("litellm", action.Enumerate); ok {
		t.Error("GetByTarget(litellm, Enumerate) returned ok, want !ok (no enumerate module for litellm)")
	}

	if _, ok := GetByTarget("unknown", action.Enumerate); ok {
		t.Error("GetByTarget(unknown, Enumerate) returned ok, want !ok")
	}
}

// TestRegisterConcurrent guards against races in Register / Get.
// Each goroutine registers a distinct ID; afterwards we verify all are
// readable. Run under `go test -race` to exercise the lock.
func TestRegisterConcurrent(t *testing.T) {
	resetRegistry()
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			id := concurrentID(i)
			Register(&fakeModule{id: id, action: action.Enumerate, target: "x"})
		}(i)
	}
	wg.Wait()

	if got := len(List()); got != n {
		t.Fatalf("List length = %d, want %d", got, n)
	}
}

func concurrentID(i int) string {
	const prefix = "concurrent."
	// keep IDs sortable but cheap to compute
	return prefix + string(rune('a'+i/26)) + string(rune('a'+i%26))
}

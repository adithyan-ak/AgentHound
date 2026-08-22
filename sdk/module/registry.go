package module

import (
	"fmt"
	"sort"
	"sync"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

var (
	registryMu sync.RWMutex
	registry   = map[string]Module{}
)

// Register adds m to the process-global registry. Panics on duplicate ID
// because registration happens at init() time and a duplicate is a
// programmer error, not a runtime condition.
func Register(m Module) {
	if m == nil {
		panic("module.Register: nil module")
	}
	id := m.ID()
	if id == "" {
		panic("module.Register: empty ID")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := registry[id]; ok {
		panic(fmt.Sprintf("module.Register: duplicate ID %q (existing=%T new=%T)", id, existing, m))
	}
	registry[id] = m
}

// Get returns the module registered under id and whether it was found.
func Get(id string) (Module, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	m, ok := registry[id]
	return m, ok
}

// List returns all registered modules sorted by ID.
func List() []Module {
	registryMu.RLock()
	out := make([]Module, 0, len(registry))
	for _, m := range registry {
		out = append(out, m)
	}
	registryMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// ListByAction returns all registered modules whose Action() == a, sorted
// by ID.
func ListByAction(a action.Action) []Module {
	registryMu.RLock()
	var out []Module
	for _, m := range registry {
		if m.Action() == a {
			out = append(out, m)
		}
	}
	registryMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// GetByTarget resolves a (targetKind, action) pair to the single module that
// handles it. The autonomous planner uses this after fingerprinting.
// Returns false if no module matches; the caller decides how to surface
// the miss. If multiple modules match (a configuration error), the first
// in ID-sorted order wins — Register would have panicked on duplicate IDs,
// so collisions only happen when two distinct modules legitimately claim
// the same (target, action) pair.
func GetByTarget(targetKind string, a action.Action) (Module, bool) {
	registryMu.RLock()
	var matches []Module
	for _, m := range registry {
		if m.Target() == targetKind && m.Action() == a {
			matches = append(matches, m)
		}
	}
	registryMu.RUnlock()
	if len(matches) == 0 {
		return nil, false
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ID() < matches[j].ID() })
	return matches[0], true
}

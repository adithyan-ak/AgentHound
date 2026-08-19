package cli

import (
	"context"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// Candidate is one fully bound unit of local planner work. Inputs may contain
// raw credential material and are never serialized.
type Candidate struct {
	Key          string
	Priority     int
	ModuleID     string
	Target       action.Target
	CredentialID string
	ResourceID   string
	PathNodeIDs  []string
	Inputs       map[string]string
}

type Result struct {
	Graph      ingest.GraphData
	NewTargets []action.Target
	Outcome    string
}

type PlannerAction interface {
	ID() string
	Candidates(View) []Candidate
	Execute(context.Context, Candidate, Journal) (Result, error)
}

// Journal is the mutation durability boundary. A mutator must Prepare before
// its first write and mark each subsequent transition immediately.
type Journal interface {
	Prepare(actionID string, recovery ingest.RecoveryRecord) error
	MarkApplied(recoveryID string) error
	MarkRestored(recoveryID string) error
}

// View is rebuilt after every result. It intentionally offers only indexed
// facts; planning remains deterministic standard-library code.
type View struct {
	Graph       ingest.GraphData
	Nodes       map[string]ingest.Node
	Outgoing    map[string][]ingest.Edge
	Incoming    map[string][]ingest.Edge
	ByKind      map[string][]ingest.Node
	Targets     []action.Target
	Credentials map[string]string
	Completed   map[string]bool
	Deep        bool
	Stealth     bool
}

func buildPlannerView(
	graph ingest.GraphData,
	targets []action.Target,
	completed map[string]bool,
	deep, stealth bool,
) View {
	view := View{
		Graph: graph, Nodes: make(map[string]ingest.Node),
		Outgoing: make(map[string][]ingest.Edge), Incoming: make(map[string][]ingest.Edge),
		ByKind: make(map[string][]ingest.Node), Targets: append([]action.Target(nil), targets...),
		Credentials: make(map[string]string), Completed: completed, Deep: deep, Stealth: stealth,
	}
	for _, fragment := range graph.Nodes {
		node, exists := view.Nodes[fragment.ID]
		if !exists {
			node = fragment
			node.Kinds = append([]string(nil), fragment.Kinds...)
			node.Properties = make(map[string]any, len(fragment.Properties))
		} else {
			node.Kinds = uniqueStrings(append(node.Kinds, fragment.Kinds...))
		}
		for key, value := range fragment.Properties {
			node.Properties[key] = value
		}
		view.Nodes[fragment.ID] = node
	}
	ids := make([]string, 0, len(view.Nodes))
	for id := range view.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		node := view.Nodes[id]
		for _, kind := range node.Kinds {
			view.ByKind[kind] = append(view.ByKind[kind], node)
		}
		if containsPlannerString(node.Kinds, "Credential") {
			materialStatus, _ := node.Properties["material_status"].(string)
			if materialStatus != string(common.CredentialMaterialObserved) {
				continue
			}
			value, _ := node.Properties["value"].(string)
			if strings.TrimSpace(value) != "" {
				view.Credentials[id] = value
			}
		}
	}
	for _, edge := range graph.Edges {
		view.Outgoing[edge.Source] = append(view.Outgoing[edge.Source], edge)
		view.Incoming[edge.Target] = append(view.Incoming[edge.Target], edge)
	}
	for key := range view.Outgoing {
		sortEdges(view.Outgoing[key])
	}
	for key := range view.Incoming {
		sortEdges(view.Incoming[key])
	}
	return view
}

func nextPlannerCandidate(actions []PlannerAction, view View) (PlannerAction, Candidate, bool) {
	type planned struct {
		action    PlannerAction
		candidate Candidate
	}
	var all []planned
	for _, plannerAction := range actions {
		if plannerAction == nil {
			continue
		}
		for _, candidate := range plannerAction.Candidates(view) {
			if candidate.Key == "" || view.Completed[candidate.Key] {
				continue
			}
			all = append(all, planned{action: plannerAction, candidate: candidate})
		}
	}
	if len(all) == 0 {
		return nil, Candidate{}, false
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].candidate.Priority != all[j].candidate.Priority {
			return all[i].candidate.Priority < all[j].candidate.Priority
		}
		if all[i].candidate.Key != all[j].candidate.Key {
			return all[i].candidate.Key < all[j].candidate.Key
		}
		return all[i].action.ID() < all[j].action.ID()
	})
	return all[0].action, all[0].candidate, true
}

func candidateKey(moduleID, target, valueHash, resource string, deep bool) string {
	if valueHash == "" {
		valueHash = "anonymous"
	}
	return strings.Join([]string{
		moduleID,
		canonicalTarget(target),
		valueHash,
		resource,
		map[bool]string{true: "deep", false: "normal"}[deep],
	}, "\x00")
}

func canonicalTarget(value string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(value)), "/")
}

func sortEdges(edges []ingest.Edge) {
	sort.Slice(edges, func(i, j int) bool {
		left := edges[i].Kind + "\x00" + edges[i].Source + "\x00" + edges[i].Target
		right := edges[j].Kind + "\x00" + edges[j].Source + "\x00" + edges[j].Target
		return left < right
	})
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// orderedCredentialIDs makes value-hash deduplication deterministic and
// preserves the most relevant attribution. A credential directly associated
// with the target always precedes an unrelated credential with the same raw
// value; ties use the stable node ID.
func orderedCredentialIDs(view View, direct map[string]bool) []string {
	ids := make([]string, 0, len(view.Credentials))
	for id := range view.Credentials {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if direct[ids[i]] != direct[ids[j]] {
			return direct[ids[i]]
		}
		return ids[i] < ids[j]
	})
	return ids
}

func containsPlannerString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

package graph

import (
	"sort"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// physObservation is one physical node observation of a logical objectid: the
// property map and label set as stored for a single generation.
type physObservation struct {
	props  map[string]any
	labels []string
}

// mergeObservations collapses several physical observations of the SAME logical
// objectid into one deterministic logical node — the read-side realisation of
// the historical MERGE-on-objectid.
//
// Deterministic property-conflict semantics (replacing the prior
// "greatest-generation_id wins", which ordered by a RANDOM UUID and so carried
// no real precedence): observations are ordered by an explicit, documented
// precedence and properties are applied in ascending order so the
// highest-precedence observation wins any conflicting key. Precedence, highest
// last (winner):
//
//  1. collector authority — a live protocol probe (mcp/a2a) outranks declared
//     config, which outranks a merged bundle, which outranks loot/unknown. See
//     collectorAuthority.
//  2. capture time — a later collection capture wins.
//  3. completion time — a later observation write/completion wins.
//  4. generation_id — a stable lexicographic final tie-break.
//
// The union of all keys is kept, so a config observation (env vars, command)
// and an mcp observation (capabilities) of one MCPServer merge into a single
// node carrying both, while duplicate physical rows never leak as separate
// logical nodes. Labels are unioned with a stable order (primary kind of the
// winning observation first).
func mergeObservations(objectID string, obs []physObservation) ingest.Node {
	if len(obs) == 0 {
		return ingest.Node{ID: objectID}
	}
	ordered := make([]physObservation, len(obs))
	copy(ordered, obs)
	sort.SliceStable(ordered, func(i, j int) bool {
		return lessObservationPrecedence(observationKey(ordered[i]), observationKey(ordered[j]))
	})

	merged := make(map[string]any)
	for _, o := range ordered {
		for k, v := range o.props {
			merged[k] = v
		}
	}
	// The winning (highest-precedence) observation is last in ascending order.
	winner := ordered[len(ordered)-1]
	labels := unionLabels(winner.labels, ordered)
	return ingest.Node{
		ID:         objectID,
		Kinds:      labels,
		Properties: merged,
	}
}

// unionLabels returns the union of every observation's labels, keeping the
// winner's label order first (so the primary kind stays first) and appending any
// additional labels in a stable, sorted order.
func unionLabels(primary []string, obs []physObservation) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(primary))
	for _, l := range primary {
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	var extra []string
	for _, o := range obs {
		for _, l := range o.labels {
			if l == "" || seen[l] {
				continue
			}
			seen[l] = true
			extra = append(extra, l)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// observationPrecedence is the comparable precedence key for a physical
// observation. Higher precedence wins a conflicting property; the fields are
// compared in declaration order (authority, then capture time, then completion
// time, then generation_id as a stable final tie-break).
type observationPrecedence struct {
	authority int
	captured  time.Time
	completed time.Time
	genID     string
}

// observationKey extracts the precedence key from an observation's stored
// properties. Missing provenance (source_collector / captured_at / last_seen)
// degrades to the lowest authority, zero time, and the generation_id tie-break,
// so a legacy observation still orders deterministically.
func observationKey(o physObservation) observationPrecedence {
	return observationPrecedence{
		authority: collectorAuthority(stringProp(o.props, "source_collector")),
		captured:  timeProp(o.props, "captured_at"),
		completed: timeProp(o.props, "last_seen"),
		genID:     stringProp(o.props, "generation_id"),
	}
}

// lessObservationPrecedence reports whether a sorts BEFORE b in ascending
// precedence order — i.e. b is the more authoritative/recent observation. The
// sort is applied ascending and the last element (greatest precedence) wins, so
// this returns true when a is the weaker observation.
func lessObservationPrecedence(a, b observationPrecedence) bool {
	if a.authority != b.authority {
		return a.authority < b.authority
	}
	if !a.captured.Equal(b.captured) {
		return a.captured.Before(b.captured)
	}
	if !a.completed.Equal(b.completed) {
		return a.completed.Before(b.completed)
	}
	return a.genID < b.genID
}

// collectorAuthority ranks a source collector for logical-projection conflict
// resolution. A higher rank wins a conflicting property. The ranking is FIXED
// and documented so the winner is deterministic AND meaningful.
//
// Rationale: a live protocol probe (mcp/a2a) observes the running service
// directly, so on a genuine conflict its value is preferred over a statically
// declared config value; declared config is authoritative for its own declared
// fields (env vars, command), but those are disjoint from probe fields and are
// preserved by the key union rather than decided here. A merged bundle ("scan",
// which also carries loot envelopes) and unknown sources rank lowest.
func collectorAuthority(collector string) int {
	switch collector {
	case "mcp":
		return 5
	case "a2a":
		return 4
	case "config":
		return 3
	case "scan":
		return 2
	default:
		return 1
	}
}

// stringProp reads a string property, returning "" when absent or non-string.
func stringProp(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	if s, ok := props[key].(string); ok {
		return s
	}
	return ""
}

// timeProp reads a timestamp property, tolerating both a driver time.Time
// (Neo4j datetime) and an RFC3339 string. Returns the zero time when absent or
// unparseable, which orders before any real timestamp.
func timeProp(props map[string]any, key string) time.Time {
	if props == nil {
		return time.Time{}
	}
	switch v := props[key].(type) {
	case time.Time:
		return v
	case string:
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

// dedupEdgesLogical collapses physical edge rows that share a logical
// (source objectid, kind, target objectid) triple, choosing ONE deterministic
// representative per triple by the same precedence used for node observations
// (collector authority, then capture time, completion time, generation_id).
// This replaces the prior "keep the first-seen row", whose result depended on
// the driver's row order. Triples are emitted in the order they are first seen
// so a caller's stable ordering is preserved.
func dedupEdgesLogical(edges []ingest.Edge) []ingest.Edge {
	if len(edges) <= 1 {
		return edges
	}
	type triple [3]string
	order := make([]triple, 0, len(edges))
	groups := make(map[triple][]ingest.Edge, len(edges))
	for _, e := range edges {
		k := triple{e.Source, e.Kind, e.Target}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], e)
	}
	out := make([]ingest.Edge, 0, len(order))
	for _, k := range order {
		out = append(out, pickEdgeRepresentative(groups[k]))
	}
	return out
}

// pickEdgeRepresentative returns the highest-precedence edge among physical
// observations of one logical triple, using the edge's stored provenance
// (source_collector / captured_at / last_seen / generation_id). Deterministic
// regardless of input order.
func pickEdgeRepresentative(edges []ingest.Edge) ingest.Edge {
	best := edges[0]
	bestKey := edgeKey(best)
	for _, e := range edges[1:] {
		k := edgeKey(e)
		if lessObservationPrecedence(bestKey, k) {
			best, bestKey = e, k
		}
	}
	return best
}

// pickEdgePropsRepresentative returns the highest-precedence property map among
// the physical observations of one logical edge triple, used by the scoped edge
// listing which collects all observations' properties in Cypher and reduces to
// one representative deterministically here.
func pickEdgePropsRepresentative(propsList []map[string]any) map[string]any {
	if len(propsList) == 0 {
		return nil
	}
	best := propsList[0]
	bestKey := propsKey(best)
	for _, p := range propsList[1:] {
		k := propsKey(p)
		if lessObservationPrecedence(bestKey, k) {
			best, bestKey = p, k
		}
	}
	return best
}

func edgeKey(e ingest.Edge) observationPrecedence {
	return propsKey(e.Properties)
}

func propsKey(props map[string]any) observationPrecedence {
	return observationPrecedence{
		authority: collectorAuthority(stringProp(props, "source_collector")),
		captured:  timeProp(props, "captured_at"),
		completed: timeProp(props, "last_seen"),
		genID:     stringProp(props, "generation_id"),
	}
}

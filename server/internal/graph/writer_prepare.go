package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type nodeOwnerKey struct {
	ID        string
	Semantics ingest.NodePropertySemantics
	Domain    string
}

type nodeOwnerContribution struct {
	kindSets     [][]string
	propertySets []map[string]any
}

// prepareObservationNodes keeps each stable owner contribution separate until
// its semantic fingerprint has been computed, then unions compatible
// contributions into the minimum writer rows. Authoritative and reference-only
// rows intentionally remain separate because only the former may author
// managed properties.
func prepareObservationNodes(
	nodes []ingest.Node,
) ([]ingest.Node, map[string][]string, error) {
	if err := validateNodeConcreteKindsByID(nodes); err != nil {
		return nil, nil, err
	}

	owners := make(map[nodeOwnerKey]*nodeOwnerContribution)
	for _, node := range nodes {
		kinds := normalizedNodeKinds(node.Kinds)
		properties := factProperties(node.Properties)
		for _, domain := range normalizedDomains(node.ObservationDomains) {
			key := nodeOwnerKey{
				ID:        node.ID,
				Semantics: node.PropertySemantics,
				Domain:    domain,
			}
			owner := owners[key]
			if owner == nil {
				owner = &nodeOwnerContribution{}
				owners[key] = owner
			}
			owner.kindSets = append(owner.kindSets, kinds)
			owner.propertySets = append(owner.propertySets, properties)
		}
	}

	type finalNode struct {
		node         ingest.Node
		kindSets     [][]string
		propertySets []map[string]any
		fingerprints []string
	}
	finals := make(map[string]*finalNode)
	for _, key := range sortedNodeOwnerKeys(owners) {
		owner := owners[key]
		kinds, err := mergeNodeKindSets(key.ID, owner.kindSets)
		if err != nil {
			return nil, nil, err
		}
		properties, err := mergePropertySets(
			"node", key.ID, owner.propertySets,
		)
		if err != nil {
			return nil, nil, err
		}

		finalKey := key.ID + "\x00" + string(key.Semantics)
		final := finals[finalKey]
		if final == nil {
			final = &finalNode{node: ingest.Node{
				ID:                key.ID,
				PropertySemantics: key.Semantics,
			}}
			finals[finalKey] = final
		}
		final.node.ObservationDomains = append(
			final.node.ObservationDomains,
			key.Domain,
		)
		final.kindSets = append(final.kindSets, kinds)
		final.propertySets = append(final.propertySets, properties)

		if key.Semantics == ingest.NodePropertySemanticsReferenceOnly {
			continue
		}
		fingerprints, err := observationFactFingerprints(
			[]string{key.Domain},
			map[string]any{
				"kinds":      kinds,
				"properties": fingerprintProperties(properties),
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("fingerprint node %s: %w", key.ID, err)
		}
		final.fingerprints = append(final.fingerprints, fingerprints...)
	}

	finalKeys := make([]string, 0, len(finals))
	for key := range finals {
		finalKeys = append(finalKeys, key)
	}
	sort.Strings(finalKeys)
	prepared := make([]ingest.Node, 0, len(finalKeys))
	fingerprints := make(map[string][]string, len(finalKeys))
	for _, key := range finalKeys {
		final := finals[key]
		kinds, err := mergeNodeKindSets(final.node.ID, final.kindSets)
		if err != nil {
			return nil, nil, err
		}
		properties, err := mergePropertySets(
			"node", final.node.ID, final.propertySets,
		)
		if err != nil {
			return nil, nil, err
		}
		final.node.Kinds = kinds
		final.node.Properties = properties
		final.node.ObservationDomains = normalizedDomains(
			final.node.ObservationDomains,
		)
		sort.Strings(final.fingerprints)
		fingerprints[nodePreparationKey(final.node)] = append(
			[]string{},
			final.fingerprints...,
		)
		prepared = append(prepared, final.node)
	}
	return prepared, fingerprints, nil
}

type edgeOwnerKey struct {
	Source      string
	Kind        string
	Target      string
	Semantics   ingest.ObservationSemantics
	DomainGroup string
}

type edgeOwnerContribution struct {
	domains      []string
	sourceKinds  []string
	targetKinds  []string
	propertySets []map[string]any
}

func prepareObservationEdges(
	edges []ingest.Edge,
) ([]ingest.Edge, map[string][]string, error) {
	owners := make(map[edgeOwnerKey]*edgeOwnerContribution)
	semanticsByEdge := make(map[string]map[ingest.ObservationSemantics]bool)
	dependencyGroupsByEdge := make(map[string]map[string]bool)

	for _, edge := range edges {
		semantics := normalizedObservationSemantics(edge.ObservationSemantics)
		edgeKey := edge.Source + "\x00" + edge.Kind + "\x00" + edge.Target
		if semanticsByEdge[edgeKey] == nil {
			semanticsByEdge[edgeKey] = make(map[ingest.ObservationSemantics]bool)
		}
		semanticsByEdge[edgeKey][semantics] = true
		domains := normalizedDomains(edge.ObservationDomains)
		domainGroups := domains
		if semantics == ingest.ObservationSemanticsAllDependencies {
			domainGroup := strings.Join(domains, "\x1f")
			domainGroups = []string{domainGroup}
			if dependencyGroupsByEdge[edgeKey] == nil {
				dependencyGroupsByEdge[edgeKey] = make(map[string]bool)
			}
			dependencyGroupsByEdge[edgeKey][domainGroup] = true
		}

		for _, domainGroup := range domainGroups {
			key := edgeOwnerKey{
				Source:      edge.Source,
				Kind:        edge.Kind,
				Target:      edge.Target,
				Semantics:   semantics,
				DomainGroup: domainGroup,
			}
			owner := owners[key]
			if owner == nil {
				owner = &edgeOwnerContribution{}
				owners[key] = owner
			}
			if semantics == ingest.ObservationSemanticsAllDependencies {
				owner.domains = append([]string(nil), domains...)
			} else {
				owner.domains = []string{domainGroup}
			}
			owner.sourceKinds = append(owner.sourceKinds, edge.SourceKind)
			owner.targetKinds = append(owner.targetKinds, edge.TargetKind)
			owner.propertySets = append(owner.propertySets, factProperties(edge.Properties))
		}
	}

	logicalEdgeKeys := make([]string, 0, len(semanticsByEdge))
	for key := range semanticsByEdge {
		logicalEdgeKeys = append(logicalEdgeKeys, key)
	}
	sort.Strings(logicalEdgeKeys)
	for _, key := range logicalEdgeKeys {
		if len(semanticsByEdge[key]) != 1 {
			return nil, nil, fmt.Errorf(
				"edge %s has conflicting observation semantics",
				formatEdgePreparationKey(key),
			)
		}
		if len(dependencyGroupsByEdge[key]) > 1 {
			return nil, nil, fmt.Errorf(
				"edge %s has conflicting all_dependencies owner sets",
				formatEdgePreparationKey(key),
			)
		}
	}

	type finalEdge struct {
		edge         ingest.Edge
		sourceKinds  []string
		targetKinds  []string
		propertySets []map[string]any
		fingerprints []string
	}
	finals := make(map[string]*finalEdge)
	for _, key := range sortedEdgeOwnerKeys(owners) {
		owner := owners[key]
		sourceKind, err := oneStringValue(
			"source kind", formatEdgeParts(key.Source, key.Kind, key.Target), owner.sourceKinds,
		)
		if err != nil {
			return nil, nil, err
		}
		targetKind, err := oneStringValue(
			"target kind", formatEdgeParts(key.Source, key.Kind, key.Target), owner.targetKinds,
		)
		if err != nil {
			return nil, nil, err
		}
		properties, err := mergePropertySets(
			"edge", formatEdgeParts(key.Source, key.Kind, key.Target), owner.propertySets,
		)
		if err != nil {
			return nil, nil, err
		}

		finalKey := key.Source + "\x00" + key.Kind + "\x00" + key.Target
		final := finals[finalKey]
		if final == nil {
			final = &finalEdge{edge: ingest.Edge{
				Source:               key.Source,
				Kind:                 key.Kind,
				Target:               key.Target,
				ObservationSemantics: key.Semantics,
			}}
			finals[finalKey] = final
		}
		final.edge.ObservationDomains = append(
			final.edge.ObservationDomains,
			owner.domains...,
		)
		final.sourceKinds = append(final.sourceKinds, sourceKind)
		final.targetKinds = append(final.targetKinds, targetKind)
		final.propertySets = append(final.propertySets, properties)

		fingerprintFact := map[string]any{
			"source_kind":           sourceKind,
			"target_kind":           targetKind,
			"observation_semantics": key.Semantics,
			"properties":            fingerprintProperties(properties),
		}
		ownerFingerprints, err := observationFactFingerprints(
			owner.domains,
			fingerprintFact,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"fingerprint edge %s: %w",
				formatEdgeParts(key.Source, key.Kind, key.Target),
				err,
			)
		}
		final.fingerprints = append(final.fingerprints, ownerFingerprints...)
	}

	finalKeys := make([]string, 0, len(finals))
	for key := range finals {
		finalKeys = append(finalKeys, key)
	}
	sort.Strings(finalKeys)
	prepared := make([]ingest.Edge, 0, len(finalKeys))
	fingerprints := make(map[string][]string, len(finalKeys))
	for _, key := range finalKeys {
		final := finals[key]
		sourceKind, err := oneStringValue(
			"source kind", formatEdgeParts(final.edge.Source, final.edge.Kind, final.edge.Target), final.sourceKinds,
		)
		if err != nil {
			return nil, nil, err
		}
		targetKind, err := oneStringValue(
			"target kind", formatEdgeParts(final.edge.Source, final.edge.Kind, final.edge.Target), final.targetKinds,
		)
		if err != nil {
			return nil, nil, err
		}
		properties, err := mergePropertySets(
			"edge",
			formatEdgeParts(final.edge.Source, final.edge.Kind, final.edge.Target),
			final.propertySets,
		)
		if err != nil {
			return nil, nil, err
		}
		final.edge.SourceKind = sourceKind
		final.edge.TargetKind = targetKind
		final.edge.Properties = properties
		final.edge.ObservationDomains = normalizedDomains(
			final.edge.ObservationDomains,
		)
		sort.Strings(final.fingerprints)
		fingerprints[edgePreparationKey(final.edge)] = append(
			[]string{},
			final.fingerprints...,
		)
		prepared = append(prepared, final.edge)
	}
	return prepared, fingerprints, nil
}

func mergePropertySets(
	factKind string,
	factID string,
	sets []map[string]any,
) (map[string]any, error) {
	keysSeen := make(map[string]bool)
	for _, properties := range sets {
		for key := range properties {
			keysSeen[key] = true
		}
	}
	keys := make([]string, 0, len(keysSeen))
	for key := range keysSeen {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	merged := make(map[string]any, len(keys))
	for _, key := range keys {
		type candidate struct {
			canonical string
			value     any
		}
		candidates := make(map[string]candidate)
		semanticDigests := make(map[string]bool)
		for _, properties := range sets {
			value, exists := properties[key]
			if !exists {
				continue
			}
			digest, err := common.CanonicalJSONHash(value)
			if err != nil {
				return nil, fmt.Errorf(
					"%s %q property %q is not canonically serializable: %w",
					factKind, factID, key, err,
				)
			}
			canonical := fmt.Sprintf("%T\x00%s", value, digest)
			if stringValue, ok := value.(string); ok && isObservationVolatileProperty(key) {
				canonical = "string\x00" + stringValue
			}
			candidates[canonical] = candidate{canonical: canonical, value: value}
			semanticDigests[digest] = true
		}
		if !isObservationVolatileProperty(key) && len(semanticDigests) > 1 {
			return nil, fmt.Errorf(
				"%s %q has conflicting values for property %q",
				factKind, factID, key,
			)
		}
		candidateKeys := make([]string, 0, len(candidates))
		for candidateKey := range candidates {
			candidateKeys = append(candidateKeys, candidateKey)
		}
		sort.Strings(candidateKeys)
		if len(candidateKeys) > 0 {
			// Volatile timestamps intentionally choose the lexicographically latest
			// RFC3339 value. Equal semantic values choose a stable Go
			// representation, independent of contribution order.
			selected := candidates[candidateKeys[len(candidateKeys)-1]]
			merged[key] = selected.value
		}
	}
	return merged, nil
}

func validateNodeConcreteKindsByID(nodes []ingest.Node) error {
	kindsByID := make(map[string]map[string]bool)
	for _, node := range nodes {
		if kindsByID[node.ID] == nil {
			kindsByID[node.ID] = make(map[string]bool)
		}
		kindsByID[node.ID][ingest.ConcreteNodeKind(node.Kinds)] = true
	}
	ids := make([]string, 0, len(kindsByID))
	for id := range kindsByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if len(kindsByID[id]) > 1 {
			return fmt.Errorf("node %q has conflicting concrete kinds", id)
		}
	}
	return nil
}

func normalizedNodeKinds(kinds []string) []string {
	if len(kinds) == 0 {
		return nil
	}
	normalized := append([]string(nil), kinds...)
	if len(normalized) > 1 {
		sort.Strings(normalized[1:])
	}
	return normalized
}

func mergeNodeKindSets(id string, sets [][]string) ([]string, error) {
	concreteKinds := make(map[string]bool)
	extras := make(map[string]bool)
	for _, kinds := range sets {
		if len(kinds) == 0 {
			continue
		}
		concreteKinds[kinds[0]] = true
		for _, kind := range kinds[1:] {
			extras[kind] = true
		}
	}
	if len(concreteKinds) != 1 {
		return nil, fmt.Errorf("node %q has conflicting concrete kinds", id)
	}
	concrete := ""
	for kind := range concreteKinds {
		concrete = kind
	}
	result := []string{concrete}
	extraKinds := make([]string, 0, len(extras))
	for kind := range extras {
		extraKinds = append(extraKinds, kind)
	}
	sort.Strings(extraKinds)
	return append(result, extraKinds...), nil
}

func oneStringValue(label, factID string, values []string) (string, error) {
	unique := make(map[string]bool)
	for _, value := range values {
		unique[value] = true
	}
	if len(unique) != 1 {
		return "", fmt.Errorf("edge %q has conflicting %s values", factID, label)
	}
	for value := range unique {
		return value, nil
	}
	return "", fmt.Errorf("edge %q has no %s", factID, label)
}

func sortedNodeOwnerKeys(
	owners map[nodeOwnerKey]*nodeOwnerContribution,
) []nodeOwnerKey {
	keys := make([]nodeOwnerKey, 0, len(owners))
	for key := range owners {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ID != keys[j].ID {
			return keys[i].ID < keys[j].ID
		}
		if keys[i].Semantics != keys[j].Semantics {
			return keys[i].Semantics < keys[j].Semantics
		}
		return keys[i].Domain < keys[j].Domain
	})
	return keys
}

func sortedEdgeOwnerKeys(
	owners map[edgeOwnerKey]*edgeOwnerContribution,
) []edgeOwnerKey {
	keys := make([]edgeOwnerKey, 0, len(owners))
	for key := range owners {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := keys[i].Source + "\x00" + keys[i].Kind + "\x00" + keys[i].Target +
			"\x00" + string(keys[i].Semantics) + "\x00" + keys[i].DomainGroup
		right := keys[j].Source + "\x00" + keys[j].Kind + "\x00" + keys[j].Target +
			"\x00" + string(keys[j].Semantics) + "\x00" + keys[j].DomainGroup
		return left < right
	})
	return keys
}

func normalizedObservationSemantics(
	semantics ingest.ObservationSemantics,
) ingest.ObservationSemantics {
	if semantics == "" {
		return ingest.ObservationSemanticsAnyOwner
	}
	return semantics
}

func nodePreparationKey(node ingest.Node) string {
	return node.ID + "\x00" + string(node.PropertySemantics)
}

func edgePreparationKey(edge ingest.Edge) string {
	return edge.Source + "\x00" + edge.Kind + "\x00" + edge.Target
}

func formatEdgePreparationKey(key string) string {
	parts := strings.Split(key, "\x00")
	if len(parts) != 3 {
		return fmt.Sprintf("%q", key)
	}
	return formatEdgeParts(parts[0], parts[1], parts[2])
}

func formatEdgeParts(source, kind, target string) string {
	return source + " -[" + kind + "]-> " + target
}

func isObservationVolatileProperty(key string) bool {
	index := sort.SearchStrings(observationVolatilePropertyKeys, key)
	return index < len(observationVolatilePropertyKeys) &&
		observationVolatilePropertyKeys[index] == key
}

func observationEdgeRow(
	edge ingest.Edge,
	fingerprints []string,
	scanID string,
	completePrefixes []string,
	includeCreateProperties bool,
) map[string]any {
	properties := factProperties(edge.Properties)
	tokens, dependencyTokens := edgeObservationTokens(edge, scanID)
	row := map[string]any{
		"source":                                  edge.Source,
		"target":                                  edge.Target,
		"properties":                              properties,
		"observation_tokens":                      tokens,
		"observation_dependency_tokens":           dependencyTokens,
		"observation_semantics":                   string(edge.ObservationSemantics),
		"ownership_tokens":                        ownershipTokens(tokens, dependencyTokens),
		"observation_domain_prefixes":             observationDomainPrefixes(edge.ObservationDomains),
		"observation_fact_fingerprints":           append([]string{}, fingerprints...),
		"observation_fingerprint_domain_prefixes": observationFingerprintDomainPrefixes(edge.ObservationDomains),
		"complete_domain_prefixes":                completePrefixes,
	}
	if includeCreateProperties {
		createProperties := cloneProperties(properties)
		createProperties["__agenthound_observation_created"] = true
		createProperties["observation_tokens"] = tokens
		createProperties["observation_dependency_tokens"] = dependencyTokens
		createProperties["observation_semantics"] = string(edge.ObservationSemantics)
		row["create_properties"] = createProperties
	}
	return row
}

func sortedEdgeGroupKeys(
	groups map[edgeGroupKey][]ingest.Edge,
) []edgeGroupKey {
	keys := make([]edgeGroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := keys[i].Kind + "\x00" + keys[i].SourceKind + "\x00" + keys[i].TargetKind
		right := keys[j].Kind + "\x00" + keys[j].SourceKind + "\x00" + keys[j].TargetKind
		return left < right
	})
	return keys
}

package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

type IdentityScope string

const (
	ScopeCollectionPoint IdentityScope = "collection_point"
	ScopeNetworkContext  IdentityScope = "network_context"
	ScopeArtifactLocal   IdentityScope = "artifact"
	ScopeReference       IdentityScope = "reference"
)

type scopeRef struct {
	kind IdentityScope
	id   string
}

// ScopeArtifact converts producer-local IDs and coverage keys into the v4
// graph projection. Validation must run first: this function trusts the
// artifact's node kinds, endpoints, coverage declarations, and identity
// record, then applies one centralized policy to all collectors.
func ScopeArtifact(data *IngestData) error {
	if data == nil {
		return fmt.Errorf("ingest data is nil")
	}
	if err := data.Meta.Identity.Validate(); err != nil {
		return fmt.Errorf("collection identity: %w", err)
	}
	coverageScopes := artifactCoverageScopes(data)
	nodeScopes := artifactNodeScopes(data, coverageScopes)
	for index := range data.Graph.Nodes {
		data.Graph.Nodes[index].ObservationDomains = scopedDomains(
			data.Graph.Nodes[index].ObservationDomains,
			coverageScopes,
		)
	}
	for index := range data.Graph.Edges {
		data.Graph.Edges[index].ObservationDomains = scopedDomains(
			data.Graph.Edges[index].ObservationDomains,
			coverageScopes,
		)
	}
	scopeCoverage(data.Meta.Collection, coverageScopes, data.Meta.Identity, data.Meta.ScanID)

	idMap := make(map[string]string, len(nodeScopes))
	for rawID, scope := range nodeScopes {
		idMap[rawID] = ScopedNodeID(scope.kind, scope.id, rawID)
	}
	for index := range data.Graph.Nodes {
		node := &data.Graph.Nodes[index]
		if node.PropertySemantics == NodePropertySemanticsReferenceOnly {
			if _, authoritative := nodeScopes[node.ID]; !authoritative {
				continue
			}
		}
		rawID := node.ID
		scope, present := nodeScopes[rawID]
		if !present {
			continue
		}
		node.ID = idMap[rawID]
		if node.PropertySemantics == NodePropertySemanticsReferenceOnly {
			continue
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		node.Properties["identity_scope"] = string(scope.kind)
		node.Properties["identity_scope_id"] = scope.id
		switch scope.kind {
		case ScopeCollectionPoint:
			node.Properties["collection_point_id"] = scope.id
		case ScopeNetworkContext:
			node.Properties["collection_point_id"] = data.Meta.Identity.CollectionPointID
			node.Properties["network_context_id"] = scope.id
		case ScopeArtifactLocal:
			node.Properties["artifact_scope_id"] = scope.id
		case ScopeReference:
			node.Properties["reference_scope_id"] = scope.id
		}
		if sourceID, ok := node.Properties["source_model_id"].(string); ok {
			if scoped, present := idMap[sourceID]; present {
				node.Properties["source_model_id"] = scoped
			}
		}
	}
	for index := range data.Graph.Edges {
		edge := &data.Graph.Edges[index]
		if scoped, present := idMap[edge.Source]; present {
			edge.Source = scoped
		}
		if scoped, present := idMap[edge.Target]; present {
			edge.Target = scoped
		}
	}
	return nil
}

func ScopedNodeID(kind IdentityScope, scopeID, rawID string) string {
	return framedSHA256("agenthound-scoped-node-v1", string(kind), scopeID, rawID)
}

func ScopedCoverageKey(kind IdentityScope, scopeID, rawKey string) string {
	parts := strings.Split(rawKey, ":")
	if len(parts) != 4 {
		return ""
	}
	sum := sha256.Sum256([]byte(
		"agenthound-scoped-coverage-v1\x00" + string(kind) + "\x00" + scopeID + "\x00" + rawKey,
	))
	return parts[0] + ":" + parts[1] + ":sha256:" + hex.EncodeToString(sum[:])
}

func artifactNodeScopes(data *IngestData, coverageScopes map[string]scopeRef) map[string]scopeRef {
	identity := data.Meta.Identity
	artifactScope := scopeRef{kind: ScopeArtifactLocal, id: framedSHA256("agenthound-artifact-scope-v1", data.Meta.ScanID)}
	pointScope := scopeRef{kind: ScopeCollectionPoint, id: identity.CollectionPointID}
	networkScope := effectiveNetworkScope(identity, artifactScope)
	if identity.Quality == IdentityQualityWeak {
		scopes := make(map[string]scopeRef, len(data.Graph.Nodes))
		for _, node := range data.Graph.Nodes {
			scopes[node.ID] = artifactScope
		}
		return scopes
	}

	authoritative := make(map[string]bool)
	for _, node := range data.Graph.Nodes {
		if node.PropertySemantics != NodePropertySemanticsReferenceOnly {
			authoritative[node.ID] = true
		}
	}
	scopes := make(map[string]scopeRef)
	for _, node := range data.Graph.Nodes {
		if !authoritative[node.ID] {
			continue
		}
		kind := ConcreteNodeKind(node.Kinds)
		switch kind {
		case "ConfigFile", "InstructionFile", "AgentInstance":
			scopes[node.ID] = pointScope
		case "Identity", "Credential":
			// Local/config observations stay collection-point scoped while
			// endpoint-derived children follow the network (or artifact-local)
			// coverage that produced them. Topology inheritance below handles
			// producers that omit a child observation domain.
			if domainScope, present := commonCoverageScope(node.ObservationDomains, coverageScopes); present {
				scopes[node.ID] = domainScope
			}
		case "Host":
			if node.Properties["scope"] == "local" {
				scopes[node.ID] = pointScope
			} else {
				scopes[node.ID] = networkScope
			}
		case "MCPServer":
			if node.Properties["transport"] == "stdio" || nodeUsesLoopback(node) {
				scopes[node.ID] = pointScope
			} else {
				scopes[node.ID] = networkScope
			}
		case "A2AAgent", "OllamaInstance", "VLLMInstance", "QdrantInstance",
			"MLflowServer", "LiteLLMGateway", "JupyterServer", "LangServeApp",
			"OpenWebUIInstance":
			if nodeUsesLoopback(node) {
				scopes[node.ID] = pointScope
			} else {
				scopes[node.ID] = networkScope
			}
		}
	}

	// Child identities inherit the observable service or reference identity
	// that owns them. This preserves stdio collection-point semantics while
	// keeping endpoint-derived service observations network-context scoped.
	for pass := 0; pass < len(data.Graph.Nodes); pass++ {
		changed := false
		for _, edge := range data.Graph.Edges {
			if _, present := scopes[edge.Target]; present || !authoritative[edge.Target] {
				continue
			}
			parent, parentScoped := scopes[edge.Source]
			if parentScoped && inheritsSourceScope(edge.Kind) {
				scopes[edge.Target] = parent
				changed = true
				continue
			}
			if !authoritative[edge.Source] && inheritsReferenceScope(edge.Kind) {
				scopes[edge.Target] = scopeRef{kind: ScopeReference, id: edge.Source}
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for _, node := range data.Graph.Nodes {
		if authoritative[node.ID] {
			if _, present := scopes[node.ID]; !present {
				// Preserve the prior local fallback for an isolated identity or
				// credential whose producer supplied neither coverage nor owning
				// topology. Known endpoint-derived children were resolved above.
				if kind := ConcreteNodeKind(node.Kinds); kind == "Identity" || kind == "Credential" {
					scopes[node.ID] = pointScope
				} else {
					scopes[node.ID] = networkScope
				}
			}
		}
	}
	_, campaignSubmission := data.Meta.Extra["campaign_artifact"]
	if !campaignSubmission {
		for _, node := range data.Graph.Nodes {
			if node.PropertySemantics != NodePropertySemanticsReferenceOnly ||
				authoritative[node.ID] ||
				!referenceFollowsCoverageScope(ConcreteNodeKind(node.Kinds)) {
				continue
			}
			domainScope, present := commonCoverageScope(node.ObservationDomains, coverageScopes)
			if !present {
				continue
			}
			if existing, alreadyScoped := scopes[node.ID]; alreadyScoped && existing != domainScope {
				scopes[node.ID] = artifactScope
				continue
			}
			scopes[node.ID] = domainScope
		}
	}
	return scopes
}

func referenceFollowsCoverageScope(kind string) bool {
	switch kind {
	case "ConfigFile", "InstructionFile", "AgentInstance", "Identity", "Credential", "Host",
		"MCPServer", "MCPTool", "MCPResource", "MCPPrompt", "A2AAgent", "A2ASkill",
		"OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
		"LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance":
		return true
	default:
		return false
	}
}

func commonCoverageScope(domains []string, coverageScopes map[string]scopeRef) (scopeRef, bool) {
	var result scopeRef
	found := false
	for _, domain := range domains {
		candidate, present := coverageScopes[domain]
		if !present {
			continue
		}
		if found && candidate != result {
			return scopeRef{}, false
		}
		result = candidate
		found = true
	}
	return result, found
}

func inheritsSourceScope(kind string) bool {
	switch kind {
	case "PROVIDES_TOOL", "PROVIDES_RESOURCE", "PROVIDES_PROMPT", "ADVERTISES_SKILL",
		"PROVIDES_MODEL", "EXTRACTED_FROM", "AUTHENTICATES_WITH", "USES_CREDENTIAL",
		"HAS_ENV_VAR", "EXPOSES_CREDENTIAL":
		return true
	default:
		return false
	}
}

func inheritsReferenceScope(kind string) bool { return kind == "EXTRACTED_FROM" }

func artifactCoverageScopes(data *IngestData) map[string]scopeRef {
	result := make(map[string]scopeRef)
	identity := data.Meta.Identity
	artifact := scopeRef{kind: ScopeArtifactLocal, id: framedSHA256("agenthound-artifact-scope-v1", data.Meta.ScanID)}
	point := scopeRef{kind: ScopeCollectionPoint, id: identity.CollectionPointID}
	network := effectiveNetworkScope(identity, artifact)
	if identity.Quality == IdentityQualityWeak {
		for _, key := range data.Meta.Collection.CoverageKeys {
			result[key] = artifact
		}
		return result
	}

	for _, key := range data.Meta.Collection.CoverageKeys {
		collector := ""
		if parts := strings.Split(key, ":"); len(parts) == 4 {
			collector = parts[0]
		}
		switch collector {
		case "config":
			result[key] = point
		case "a2a":
			result[key] = endpointCoverageScope(data, key, point, network)
		case "scan":
			if _, extract := data.Meta.Extra["extract_type"]; extract {
				result[key] = point
			} else if _, campaign := data.Meta.Extra["campaign_artifact"]; campaign {
				result[key] = point
			} else if _, loot := data.Meta.Extra["loot_type"]; loot {
				result[key] = endpointCoverageScope(data, key, point, network)
			} else {
				result[key] = network
			}
		case "mcp":
			result[key] = mcpCoverageScope(data, key, point, network)
		default:
			result[key] = network
		}
	}
	return result
}

func mcpCoverageScope(data *IngestData, key string, point, network scopeRef) scopeRef {
	for _, node := range data.Graph.Nodes {
		if ConcreteNodeKind(node.Kinds) != "MCPServer" || !containsString(node.ObservationDomains, key) {
			continue
		}
		if node.Properties["transport"] == "stdio" || nodeUsesLoopback(node) {
			return point
		}
		return network
	}
	for _, outcome := range data.Meta.Collection.Outcomes {
		if outcome.CoverageKey != key {
			continue
		}
		target := strings.ToLower(strings.TrimSpace(outcome.Target))
		if endpointIsLoopback(target) {
			return point
		}
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			return network
		}
	}
	return point
}

func endpointCoverageScope(data *IngestData, key string, point, network scopeRef) scopeRef {
	for _, node := range data.Graph.Nodes {
		if containsString(node.ObservationDomains, key) && nodeUsesLoopback(node) {
			return point
		}
	}
	for _, outcome := range data.Meta.Collection.Outcomes {
		if outcome.CoverageKey == key && endpointIsLoopback(outcome.Target) {
			return point
		}
	}
	return network
}

func nodeUsesLoopback(node Node) bool {
	for _, key := range []string{"endpoint", "url", "base_url"} {
		if value, ok := node.Properties[key].(string); ok && endpointIsLoopback(value) {
			return true
		}
	}
	return false
}

func endpointIsLoopback(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	host := ""
	if err == nil {
		host = parsed.Hostname()
	}
	if host == "" {
		if splitHost, _, splitErr := net.SplitHostPort(trimmed); splitErr == nil {
			host = splitHost
		} else {
			host = strings.Trim(trimmed, "[]")
		}
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func scopeCoverage(
	report *CollectionReport,
	scopes map[string]scopeRef,
	identity CollectionIdentity,
	scanID string,
) {
	if report == nil {
		return
	}
	parentVariants := make(map[string]map[scopeRef]bool)
	for _, outcome := range report.Outcomes {
		if outcome.ParentCoverageKey == "" {
			continue
		}
		if parentVariants[outcome.ParentCoverageKey] == nil {
			parentVariants[outcome.ParentCoverageKey] = make(map[scopeRef]bool)
		}
		parentVariants[outcome.ParentCoverageKey][scopes[outcome.CoverageKey]] = true
	}
	rootKeys := make(map[string]bool, len(report.AuthoritativeRoots))
	for _, root := range report.AuthoritativeRoots {
		rootKeys[root.CoverageKey] = true
	}

	var outcomes []CollectionOutcome
	variantsByKey := make(map[string]map[scopeRef]bool)
	for _, outcome := range report.Outcomes {
		variants := map[scopeRef]bool{scopes[outcome.CoverageKey]: true}
		if parents := parentVariants[outcome.CoverageKey]; len(parents) > 0 {
			variants = parents
		}
		if rootKeys[outcome.CoverageKey] && outcome.Collector == "mcp" &&
			identity.Quality == IdentityQualityStrong {
			// One exhaustive MCP run inventories both local stdio servers and
			// services visible in the current network context. Keep those roots
			// independent so an empty run can retire both local and current-network
			// children without touching a different network context.
			variants[scopeRef{kind: ScopeCollectionPoint, id: identity.CollectionPointID}] = true
			artifact := scopeRef{kind: ScopeArtifactLocal, id: framedSHA256("agenthound-artifact-scope-v1", scanID)}
			variants[effectiveNetworkScope(identity, artifact)] = true
		}
		variantsByKey[outcome.CoverageKey] = variants
		ordered := sortedScopeRefs(variants)
		for _, scope := range ordered {
			mapped := outcome
			mapped.CoverageKey = ScopedCoverageKey(scope.kind, scope.id, outcome.CoverageKey)
			if outcome.ParentCoverageKey != "" {
				mapped.ParentCoverageKey = ScopedCoverageKey(scope.kind, scope.id, outcome.ParentCoverageKey)
			}
			outcomes = append(outcomes, mapped)
		}
	}
	report.Outcomes = outcomes

	declared := make(map[string]bool)
	for _, outcome := range report.Outcomes {
		declared[outcome.CoverageKey] = true
	}
	report.CoverageKeys = report.CoverageKeys[:0]
	for key := range declared {
		report.CoverageKeys = append(report.CoverageKeys, key)
	}
	sort.Strings(report.CoverageKeys)

	var roots []CoverageRoot
	for _, root := range report.AuthoritativeRoots {
		childrenByScope := make(map[scopeRef][]string)
		for _, child := range root.ChildCoverageKeys {
			scope := scopes[child]
			childrenByScope[scope] = append(
				childrenByScope[scope],
				ScopedCoverageKey(scope.kind, scope.id, child),
			)
		}
		variants := variantsByKey[root.CoverageKey]
		if len(variants) == 0 {
			variants = map[scopeRef]bool{scopes[root.CoverageKey]: true}
		}
		for _, scope := range sortedScopeRefs(variants) {
			children := childrenByScope[scope]
			sort.Strings(children)
			roots = append(roots, CoverageRoot{
				CoverageKey:       ScopedCoverageKey(scope.kind, scope.id, root.CoverageKey),
				ChildCoverageKeys: children,
			})
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].CoverageKey < roots[j].CoverageKey })
	report.AuthoritativeRoots = roots

}

func effectiveNetworkScope(identity CollectionIdentity, artifact scopeRef) scopeRef {
	if identity.NetworkQuality != IdentityQualityStrong {
		return artifact
	}
	return scopeRef{kind: ScopeNetworkContext, id: identity.NetworkContextID}
}

func scopedDomains(values []string, scopes map[string]scopeRef) []string {
	mapped := make([]string, 0, len(values))
	for _, value := range values {
		scope, present := scopes[value]
		if !present {
			continue
		}
		mapped = append(mapped, ScopedCoverageKey(scope.kind, scope.id, value))
	}
	return MergeObservationDomains(mapped)
}

func sortedScopeRefs(values map[scopeRef]bool) []scopeRef {
	refs := make([]scopeRef, 0, len(values))
	for value := range values {
		refs = append(refs, value)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].kind == refs[j].kind {
			return refs[i].id < refs[j].id
		}
		return refs[i].kind < refs[j].kind
	})
	return refs
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

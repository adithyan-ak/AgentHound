package ingest

import (
	"encoding/json"
	"fmt"
	"sort"
	"unicode"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type Normalizer struct{}

func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

func (n *Normalizer) Normalize(data *ingest.IngestData) []ingest.NormalizationWarning {
	var warnings []ingest.NormalizationWarning
	identityAliases := make(map[string]ingest.IdentityAliasState, len(data.Meta.IdentityAliases))
	for _, alias := range data.Meta.IdentityAliases {
		identityAliases[alias.LegacyID] = alias.State
	}

	if data.Graph.Nodes == nil {
		data.Graph.Nodes = []ingest.Node{}
	}
	if data.Graph.Edges == nil {
		data.Graph.Edges = []ingest.Edge{}
	}

	nodeKindsByID := make(map[string][]string, len(data.Graph.Nodes))
	for i := range data.Graph.Nodes {
		node := &data.Graph.Nodes[i]
		for _, kind := range node.Kinds {
			if !hasKind(nodeKindsByID[node.ID], kind) {
				nodeKindsByID[node.ID] = append(nodeKindsByID[node.ID], kind)
			}
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		normalizeMCPIdentityCompatibility(node, identityAliases)

		// Set objectid
		node.Properties["objectid"] = node.ID

		// Convert keys to snake_case and process values
		node.Properties = n.normalizeProps(node.Properties, fmt.Sprintf("node %s", node.ID), &warnings)
		normalizeLegacyLocalProcessAuth(node)
	}

	for i := range data.Graph.Edges {
		edge := &data.Graph.Edges[i]
		if endpoints, ok := ingest.EdgeKindEndpoints[edge.Kind]; ok {
			if edge.SourceKind == "" {
				edge.SourceKind = actualEndpointKind(nodeKindsByID[edge.Source], endpoints.SourceKinds)
			}
			if edge.TargetKind == "" {
				edge.TargetKind = actualEndpointKind(nodeKindsByID[edge.Target], endpoints.TargetKinds)
			}
		}
		if edge.Properties == nil {
			edge.Properties = make(map[string]any)
		}
		edge.Properties = n.normalizeProps(edge.Properties, fmt.Sprintf("edge %s->%s", edge.Source, edge.Target), &warnings)
	}

	return warnings
}

func normalizeLegacyLocalProcessAuth(node *ingest.Node) {
	evidence, _ := node.Properties["auth_evidence"].(string)
	if evidence != common.AuthEvidenceLocalProcess {
		return
	}
	method, _ := node.Properties["auth_method"].(string)
	switch common.NormalizeAuthMethod(method) {
	case common.AuthNone, common.AuthUnknown:
		node.Properties["auth_method"] = string(common.AuthUnknown)
		node.Properties["auth_assurance"] = string(common.AuthAssuranceUnknown)
	}
}

func normalizeMCPIdentityCompatibility(
	node *ingest.Node,
	aliases map[string]ingest.IdentityAliasState,
) {
	if !hasKind(node.Kinds, "MCPServer") || node.Properties["transport"] != "stdio" {
		return
	}
	scheme, _ := node.Properties["id_scheme"].(string)
	if scheme == "" {
		node.Properties["id_scheme"] = ingest.MCPStdioIdentitySchemeV1
		node.Properties["identity_compatibility"] = string(ingest.IdentityAliasUnresolved)
		if aliasState, ok := aliases[node.ID]; ok {
			node.Properties["identity_compatibility"] = string(aliasState)
			if aliasState == ingest.IdentityAliasAmbiguous {
				node.Properties["identity_quarantined"] = true
			}
		}
		return
	}
	if scheme != ingest.MCPStdioIdentitySchemeV2 {
		return
	}
	legacyID, _ := node.Properties["legacy_objectid"].(string)
	if aliasState, ok := aliases[legacyID]; ok {
		node.Properties["legacy_alias_state"] = string(aliasState)
		if aliasState == ingest.IdentityAliasAmbiguous {
			node.Properties["legacy_identity_quarantined"] = true
		}
	}
}

func actualEndpointKind(actualKinds, allowedKinds []string) string {
	for _, actualKind := range actualKinds {
		if hasKind(allowedKinds, actualKind) {
			return actualKind
		}
	}
	return ""
}

func (n *Normalizer) normalizeProps(
	props map[string]any,
	context string,
	warnings *[]ingest.NormalizationWarning,
) map[string]any {
	result := make(map[string]any, len(props))
	sourceKeys := make(map[string]string, len(props))
	keys := make([]string, 0, len(props))
	for key := range props {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		val := props[key]
		// Strip nil values
		if val == nil {
			continue
		}

		// Convert key to snake_case
		snakeKey := CamelToSnake(key)
		if prior, exists := sourceKeys[snakeKey]; exists && prior != key {
			*warnings = append(*warnings, ingest.NormalizationWarning{
				Code:              "property_key_collision",
				Status:            ingest.NormalizationStatusDegraded,
				Message:           fmt.Sprintf("dropped property %q on %s because it collides with normalized key from %q", key, context, prior),
				Context:           context,
				Property:          snakeKey,
				PublicationUnsafe: true,
			})
			continue
		}
		sourceKeys[snakeKey] = key

		// Serialize complex values to JSON strings
		switch v := val.(type) {
		case map[string]any:
			data, err := json.Marshal(v)
			if err == nil {
				result[snakeKey] = string(data)
				*warnings = append(*warnings, serializedPropertyWarning(snakeKey, context))
			} else {
				*warnings = append(*warnings, droppedPropertyWarning(snakeKey, context, err))
			}
		case []any:
			if isHomogeneous(v) {
				result[snakeKey] = v
			} else {
				data, err := json.Marshal(v)
				if err == nil {
					result[snakeKey] = string(data)
					*warnings = append(*warnings, serializedPropertyWarning(snakeKey, context))
				} else {
					*warnings = append(*warnings, droppedPropertyWarning(snakeKey, context, err))
				}
			}
		case json.Number:
			if i, err := v.Int64(); err == nil {
				result[snakeKey] = i
			} else if f, err := v.Float64(); err == nil {
				result[snakeKey] = f
			} else {
				result[snakeKey] = v.String()
			}
		default:
			result[snakeKey] = val
		}
	}

	return result
}

func serializedPropertyWarning(property, context string) ingest.NormalizationWarning {
	return ingest.NormalizationWarning{
		Code:              "complex_property_serialized",
		Status:            ingest.NormalizationStatusWarning,
		Message:           fmt.Sprintf("serialized complex property %q on %s to JSON string", property, context),
		Context:           context,
		Property:          property,
		PublicationUnsafe: false,
	}
}

func droppedPropertyWarning(property, context string, err error) ingest.NormalizationWarning {
	return ingest.NormalizationWarning{
		Code:              "property_dropped",
		Status:            ingest.NormalizationStatusDegraded,
		Message:           fmt.Sprintf("dropped unsupported property %q on %s: %v", property, context, err),
		Context:           context,
		Property:          property,
		PublicationUnsafe: true,
	}
}

// CamelToSnake converts camelCase/PascalCase to snake_case.
// Handles consecutive uppercase: HTTPServer -> http_server, scanID -> scan_id
func CamelToSnake(s string) string {
	if s == "" {
		return s
	}

	runes := []rune(s)
	var result []rune

	for i, r := range runes {
		if unicode.IsUpper(r) {
			if i > 0 {
				prev := runes[i-1]
				if unicode.IsLower(prev) || unicode.IsDigit(prev) {
					// aB -> a_b
					result = append(result, '_')
				} else if unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
					// ABc -> a_bc (end of uppercase run before lowercase)
					result = append(result, '_')
				}
			}
			result = append(result, unicode.ToLower(r))
		} else {
			result = append(result, r)
		}
	}

	return string(result)
}

func isHomogeneous(arr []any) bool {
	if len(arr) == 0 {
		return true
	}
	switch arr[0].(type) {
	case string:
		for _, v := range arr[1:] {
			if _, ok := v.(string); !ok {
				return false
			}
		}
		return true
	case float64:
		for _, v := range arr[1:] {
			if _, ok := v.(float64); !ok {
				return false
			}
		}
		return true
	case bool:
		for _, v := range arr[1:] {
			if _, ok := v.(bool); !ok {
				return false
			}
		}
		return true
	case int64:
		for _, v := range arr[1:] {
			if _, ok := v.(int64); !ok {
				return false
			}
		}
		return true
	default:
		return false
	}
}

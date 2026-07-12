package ingest

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type Normalizer struct{}

func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

func (n *Normalizer) Normalize(data *ingest.IngestData) []ingest.NormalizationWarning {
	var warnings []ingest.NormalizationWarning

	if data.Graph.Nodes == nil {
		data.Graph.Nodes = []ingest.Node{}
	}
	if data.Graph.Edges == nil {
		data.Graph.Edges = []ingest.Edge{}
	}

	for i := range data.Graph.Nodes {
		node := &data.Graph.Nodes[i]
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}

		// Set objectid
		node.Properties["objectid"] = node.ID

		// Property names are already canonical: validation runs before
		// normalization and rejects non-snake-case keys.
		node.Properties = n.normalizeProps(node.Properties, fmt.Sprintf("node %s", node.ID), &warnings)
	}

	for i := range data.Graph.Edges {
		edge := &data.Graph.Edges[i]
		if edge.Properties == nil {
			edge.Properties = make(map[string]any)
		}
		edge.Properties = n.normalizeProps(edge.Properties, fmt.Sprintf("edge %s->%s", edge.Source, edge.Target), &warnings)
	}

	return warnings
}

func (n *Normalizer) normalizeProps(
	props map[string]any,
	context string,
	warnings *[]ingest.NormalizationWarning,
) map[string]any {
	result := make(map[string]any, len(props))
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

		// Serialize complex values to JSON strings
		switch v := val.(type) {
		case map[string]any:
			data, err := json.Marshal(v)
			if err == nil {
				result[key] = string(data)
				*warnings = append(*warnings, serializedPropertyWarning(key, context))
			} else {
				*warnings = append(*warnings, droppedPropertyWarning(key, context, err))
			}
		case []any:
			if isHomogeneous(v) {
				result[key] = v
			} else {
				data, err := json.Marshal(v)
				if err == nil {
					result[key] = string(data)
					*warnings = append(*warnings, serializedPropertyWarning(key, context))
				} else {
					*warnings = append(*warnings, droppedPropertyWarning(key, context, err))
				}
			}
		case json.Number:
			if i, err := v.Int64(); err == nil {
				result[key] = i
			} else if f, err := v.Float64(); err == nil {
				result[key] = f
			} else {
				result[key] = v.String()
			}
		default:
			result[key] = val
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

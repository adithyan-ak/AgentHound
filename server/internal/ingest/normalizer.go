package ingest

import (
	"encoding/json"
	"fmt"
	"unicode"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type Normalizer struct{}

func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

func (n *Normalizer) Normalize(data *ingest.IngestData) []string {
	var warnings []string

	for i := range data.Graph.Nodes {
		node := &data.Graph.Nodes[i]
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}

		// Set objectid
		node.Properties["objectid"] = node.ID

		// Convert keys to snake_case and process values
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

func (n *Normalizer) normalizeProps(props map[string]any, context string, warnings *[]string) map[string]any {
	result := make(map[string]any, len(props))

	for key, val := range props {
		// Strip nil values
		if val == nil {
			continue
		}

		// Convert key to snake_case
		snakeKey := CamelToSnake(key)

		// Serialize complex values to JSON strings
		switch v := val.(type) {
		case map[string]any:
			data, err := json.Marshal(v)
			if err == nil {
				result[snakeKey] = string(data)
				*warnings = append(*warnings, fmt.Sprintf("serialized complex property %q on %s to JSON string", snakeKey, context))
			}
		case []any:
			if isHomogeneous(v) {
				result[snakeKey] = v
			} else {
				data, err := json.Marshal(v)
				if err == nil {
					result[snakeKey] = string(data)
					*warnings = append(*warnings, fmt.Sprintf("serialized complex property %q on %s to JSON string", snakeKey, context))
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

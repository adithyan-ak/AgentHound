package processors

func stringSliceProperty(properties map[string]any, key string) []string {
	switch values := properties[key].(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil
			}
			result = append(result, text)
		}
		return result
	default:
		return nil
	}
}

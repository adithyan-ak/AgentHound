package ingest

func int64Property(properties map[string]any, key string) (int64, bool) {
	switch value := properties[key].(type) {
	case int:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		return int64(value), true
	default:
		return 0, false
	}
}

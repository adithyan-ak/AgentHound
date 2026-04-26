package riskscore

var trustsServerWeights = map[string]float64{
	"none":   0.1,
	"apiKey": 0.3,
	"bearer": 0.5,
	"oauth":  0.7,
	"mtls":   0.9,
}

var staticEdgeWeights = map[string]float64{
	"PROVIDES_TOOL":     0.1,
	"HAS_ACCESS_TO":     0.2,
	"CAN_EXECUTE":       0.1,
	"SHADOWS":           0.4,
	"CAN_IMPERSONATE":   0.6,
	"PROVIDES_RESOURCE": 0.2,
	"PROVIDES_PROMPT":   0.1,
}

func EdgeRiskWeight(edgeKind, authMethod string) float64 {
	switch edgeKind {
	case "TRUSTS_SERVER":
		if w, ok := trustsServerWeights[authMethod]; ok {
			return w
		}
		return trustsServerWeights["none"]
	case "DELEGATES_TO":
		if authMethod != "" && authMethod != "none" {
			return 0.5
		}
		return 0.1
	default:
		if w, ok := staticEdgeWeights[edgeKind]; ok {
			return w
		}
		return 0.5
	}
}

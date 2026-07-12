package processors

import "github.com/adithyan-ak/agenthound/sdk/ingest"

func managedProcessorNodes(nodes []ingest.Node) []ingest.Node {
	result := append([]ingest.Node(nil), nodes...)
	for i := range result {
		if len(result[i].ObservationDomains) == 0 {
			result[i].ObservationDomains = []string{"processor-test-domain"}
		}
	}
	return result
}

func managedProcessorEdges(edges []ingest.Edge) []ingest.Edge {
	result := append([]ingest.Edge(nil), edges...)
	for i := range result {
		if len(result[i].ObservationDomains) == 0 {
			result[i].ObservationDomains = []string{"processor-test-domain"}
		}
	}
	return result
}

func compositeProcessorEdges(edges []ingest.Edge) []ingest.Edge {
	result := append([]ingest.Edge(nil), edges...)
	for i := range result {
		properties := make(map[string]any, len(result[i].Properties)+1)
		for key, value := range result[i].Properties {
			properties[key] = value
		}
		properties["is_composite"] = true
		result[i].Properties = properties
	}
	return result
}

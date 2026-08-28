package ingest

import "testing"

func TestConcreteNodeKindAcceptsOnlyDocumentedUmbrellaCompanions(t *testing.T) {
	for _, test := range []struct {
		name  string
		kinds []string
		want  string
	}{
		{"single concrete", []string{"MCPServer"}, "MCPServer"},
		{"service umbrella", []string{"LiteLLMGateway", "AIService"}, "LiteLLMGateway"},
		{"conflicting concrete kinds", []string{"MCPServer", "MCPTool"}, ""},
		{"undocumented umbrella companion", []string{"MCPServer", "AIService"}, ""},
		{"umbrella first", []string{"AIService", "LiteLLMGateway"}, ""},
		{"umbrella only", []string{"AIService"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ConcreteNodeKind(test.kinds); got != test.want {
				t.Fatalf("ConcreteNodeKind(%v) = %q, want %q", test.kinds, got, test.want)
			}
		})
	}
}

// TestProvidesResource_AcceptsHistoricalAndTypedPairs locks exact endpoint
// pairs so additive V1 support does not make every service/resource cross-pair
// semantically valid.
func TestProvidesResource_AcceptsMLflowAndQdrantSources(t *testing.T) {
	ep, ok := EdgeKindEndpoints["PROVIDES_RESOURCE"]
	if !ok {
		t.Fatal("PROVIDES_RESOURCE missing from EdgeKindEndpoints")
	}
	wantSources := map[string]bool{
		"MCPServer": true, "JupyterServer": true,
		"MLflowServer": true, "QdrantInstance": true,
	}
	got := map[string]bool{}
	for _, s := range ep.SourceKinds {
		got[s] = true
	}
	for k := range wantSources {
		if !got[k] {
			t.Errorf("PROVIDES_RESOURCE source-kinds missing %q; got %v", k, ep.SourceKinds)
		}
	}
	for _, src := range []string{"MLflowServer", "QdrantInstance"} {
		if !SourceKindAllowed("PROVIDES_RESOURCE", src) {
			t.Errorf("PROVIDES_RESOURCE must accept explicit source %q", src)
		}
		if !TargetKindAllowed("PROVIDES_RESOURCE", "MCPResource") {
			t.Error("PROVIDES_RESOURCE must accept explicit MCPResource target")
		}
	}
	wantPairs := []EdgeEndpointPair{
		{SourceKind: "MCPServer", TargetKind: "MCPResource"},
		{SourceKind: "JupyterServer", TargetKind: "WorkspaceFile"},
		{SourceKind: "MLflowServer", TargetKind: "ModelArtifact"},
		{SourceKind: "QdrantInstance", TargetKind: "VectorCollection"},
	}
	for _, pair := range wantPairs {
		if !EndpointKindsAllowed("PROVIDES_RESOURCE", pair.SourceKind, pair.TargetKind) {
			t.Errorf("PROVIDES_RESOURCE rejected %s -> %s", pair.SourceKind, pair.TargetKind)
		}
	}
	for _, pair := range []EdgeEndpointPair{
		{SourceKind: "MCPServer", TargetKind: "VectorCollection"},
		{SourceKind: "QdrantInstance", TargetKind: "WorkspaceFile"},
	} {
		if EndpointKindsAllowed("PROVIDES_RESOURCE", pair.SourceKind, pair.TargetKind) {
			t.Errorf("PROVIDES_RESOURCE accepted invalid %s -> %s", pair.SourceKind, pair.TargetKind)
		}
	}
}

func TestEdgeKindEndpoints_ReflectsProducedVariants(t *testing.T) {
	if !TargetKindAllowed("CAN_REACH", "Credential") {
		t.Fatal("CAN_REACH must permit the credential-chain processor's Credential target")
	}
	if !SourceKindAllowed("EXPOSES", "OpenWebUIInstance") {
		t.Fatal("EXPOSES must permit OpenWebUIInstance producer labels")
	}
	if !TargetKindAllowed("EXPOSES", "OllamaInstance") {
		t.Fatal("EXPOSES must permit OllamaInstance producer labels")
	}
}

func TestEndpointKindAllowed_FailsClosedForUnknownEdge(t *testing.T) {
	if SourceKindAllowed("MADE_UP_KIND", "MCPServer") {
		t.Fatal("unknown edge kind must not accept a source kind")
	}
	if TargetKindAllowed("MADE_UP_KIND", "MCPTool") {
		t.Fatal("unknown edge kind must not accept a target kind")
	}
}

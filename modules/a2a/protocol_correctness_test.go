package a2a

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestParseV030RetainsNonconformantCard(t *testing.T) {
	raw := validV030Card()
	delete(raw, "defaultOutputModes")

	card, err := parseV030(raw, "hash-v030", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV030: %v", err)
	}
	if card.Conformant {
		t.Fatal("card missing a required field was marked conformant")
	}
	if !containsString(card.ConformanceErrors, "defaultOutputModes: required field is missing") {
		t.Fatalf("conformance errors = %v", card.ConformanceErrors)
	}
	if card.Name != "Legacy Agent" || card.CardHash != "hash-v030" {
		t.Fatalf("nonconformant observation was not retained: %+v", card)
	}
}

func TestParseV10ValidatesRequiredArraysAndNestedFields(t *testing.T) {
	raw := validV10Card()
	raw["supportedInterfaces"] = []any{}
	raw["skills"] = []any{
		map[string]any{
			"id":          "summarize",
			"name":        "Summarize",
			"description": "Summarizes input",
			"tags":        []any{},
		},
	}

	card, err := parseV10(raw, "hash-v1", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if card.Conformant {
		t.Fatal("card with empty required arrays was marked conformant")
	}
	for _, want := range []string{
		"supportedInterfaces: required array must contain at least one element",
		"skills[0].tags: required array must contain at least one element",
	} {
		if !containsString(card.ConformanceErrors, want) {
			t.Errorf("missing %q in %v", want, card.ConformanceErrors)
		}
	}
}

func TestParseV10PreservesOrderedInterfacesAndFirstPreferred(t *testing.T) {
	raw := validV10Card()
	raw["supportedInterfaces"] = []any{
		map[string]any{
			"url":             "https://agent.example/grpc",
			"protocolBinding": "GRPC",
			"protocolVersion": "1.0",
			"tenant":          "tenant-a",
		},
		map[string]any{
			"url":             "https://agent.example/jsonrpc",
			"protocolBinding": "JSONRPC",
			"protocolVersion": "1.0",
		},
		map[string]any{
			"url":             "https://agent.example/rest",
			"protocolBinding": "HTTP+JSON",
			"protocolVersion": "1.1",
		},
	}

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if card.URL != "https://agent.example/grpc" {
		t.Fatalf("preferred URL = %q, want first interface", card.URL)
	}
	if len(card.Interfaces) != 3 {
		t.Fatalf("interfaces = %+v", card.Interfaces)
	}
	gotBindings := []string{
		card.Interfaces[0].ProtocolBinding,
		card.Interfaces[1].ProtocolBinding,
		card.Interfaces[2].ProtocolBinding,
	}
	if !reflect.DeepEqual(gotBindings, []string{"GRPC", "JSONRPC", "HTTP+JSON"}) {
		t.Fatalf("interface order changed: %v", gotBindings)
	}
	if !card.Interfaces[0].Preferred || card.Interfaces[1].Preferred || card.Interfaces[2].Preferred {
		t.Fatalf("preferred markers = %+v", card.Interfaces)
	}
	if !reflect.DeepEqual(card.ProtocolVersions, []string{"1.0", "1.1"}) {
		t.Fatalf("protocol versions = %v", card.ProtocolVersions)
	}
}

func TestParseV10AcceptsAbsoluteWSSCustomInterface(t *testing.T) {
	raw := validV10Card()
	raw["supportedInterfaces"] = []any{
		map[string]any{
			"url":             "wss://agent.example/a2a/websocket",
			"protocolBinding": "https://example.com/bindings/websocket/v1",
			"protocolVersion": "1.0",
		},
	}

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if !card.Conformant || len(card.Interfaces) != 1 || !card.Interfaces[0].Conformant {
		t.Fatalf("valid custom interface rejected: %+v errors=%v", card.Interfaces, card.ConformanceErrors)
	}
}

func TestSecuritySchemeValuesMustBeUsable(t *testing.T) {
	v030 := parseV030SecuritySchemes(map[string]any{
		"securitySchemes": map[string]any{
			"bad": map[string]any{"type": "apiKey", "in": "body", "name": ""},
		},
	})
	if len(v030) != 1 || v030[0].Conformant {
		t.Fatalf("invalid v0.3 API-key scheme accepted: %+v", v030)
	}

	v10 := parseV10SecuritySchemes(map[string]any{
		"securitySchemes": map[string]any{
			"bad": map[string]any{
				"apiKeySecurityScheme": map[string]any{"location": "body", "name": ""},
			},
		},
	})
	if len(v10) != 1 || v10[0].Conformant {
		t.Fatalf("invalid v1 API-key scheme accepted: %+v", v10)
	}

	v030OAuth := parseV030SecuritySchemes(map[string]any{
		"securitySchemes": map[string]any{
			"bad": map[string]any{"type": "oauth2", "flows": map[string]any{}},
		},
	})
	if len(v030OAuth) != 1 || v030OAuth[0].Conformant {
		t.Fatalf("empty v0.3 OAuth flows accepted: %+v", v030OAuth)
	}

	v10OAuth := parseV10SecuritySchemes(map[string]any{
		"securitySchemes": map[string]any{
			"bad": map[string]any{
				"oauth2SecurityScheme": map[string]any{
					"flows": map[string]any{
						"implicit": map[string]any{
							"authorizationUrl": "",
							"scopes":           map[string]any{},
						},
					},
				},
			},
		},
	})
	if len(v10OAuth) != 1 || v10OAuth[0].Conformant {
		t.Fatalf("empty v1 OAuth URL accepted: %+v", v10OAuth)
	}
}

func TestParseV030PreservesPreferredAndAdditionalInterfaces(t *testing.T) {
	raw := validV030Card()
	raw["preferredTransport"] = "GRPC"
	raw["additionalInterfaces"] = []any{
		map[string]any{"url": "https://legacy.example/jsonrpc", "transport": "JSONRPC"},
		map[string]any{"url": "https://legacy.example/rest", "transport": "HTTP+JSON"},
	}

	card, err := parseV030(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV030: %v", err)
	}
	if len(card.Interfaces) != 3 {
		t.Fatalf("interfaces = %+v", card.Interfaces)
	}
	if card.Interfaces[0].URL != "https://legacy.example/a2a" ||
		card.Interfaces[0].ProtocolBinding != "GRPC" ||
		!card.Interfaces[0].Preferred {
		t.Fatalf("preferred interface = %+v", card.Interfaces[0])
	}
	if card.Interfaces[1].Preferred || card.Interfaces[2].Preferred {
		t.Fatalf("additional interface marked preferred: %+v", card.Interfaces)
	}
}

func TestVersionedSecurityRequirementsPreserveOROfAND(t *testing.T) {
	t.Run("v0.3", func(t *testing.T) {
		raw := validV030Card()
		raw["securitySchemes"] = map[string]any{
			"oauth": map[string]any{
				"type": "oauth2",
				"flows": map[string]any{
					"authorizationCode": map[string]any{
						"authorizationUrl": "https://auth.example/authorize",
						"tokenUrl":         "https://auth.example/token",
						"scopes":           map[string]any{"read": "Read"},
					},
				},
			},
			"api":  map[string]any{"type": "apiKey", "in": "header", "name": "X-Key"},
			"mtls": map[string]any{"type": "mutualTLS"},
		}
		raw["security"] = []any{
			map[string]any{"oauth": []any{"read", "write"}},
			map[string]any{"api": []any{}, "mtls": []any{}},
		}

		card, err := parseV030(raw, "hash", testA2AEngine(t))
		if err != nil {
			t.Fatalf("parseV030: %v", err)
		}
		assertSecurityAlternatives(t, card.SecurityRequirements)
		if card.AuthMethod != "unknown" {
			t.Fatalf("ambiguous OR-of-AND auth method = %q, want unknown", card.AuthMethod)
		}
	})

	t.Run("v1", func(t *testing.T) {
		raw := validV10Card()
		raw["securitySchemes"] = map[string]any{
			"oauth": map[string]any{
				"oauth2SecurityScheme": map[string]any{
					"flows": map[string]any{
						"clientCredentials": map[string]any{
							"tokenUrl": "https://auth.example/token",
							"scopes":   map[string]any{"read": "Read", "write": "Write"},
						},
					},
				},
			},
			"api": map[string]any{
				"apiKeySecurityScheme": map[string]any{"location": "header", "name": "X-Key"},
			},
			"mtls": map[string]any{
				"mtlsSecurityScheme": map[string]any{},
			},
		}
		raw["securityRequirements"] = []any{
			map[string]any{
				"schemes": map[string]any{
					"oauth": map[string]any{"list": []any{"read", "write"}},
				},
			},
			map[string]any{
				"schemes": map[string]any{
					"api":  map[string]any{"list": []any{}},
					"mtls": map[string]any{"list": []any{}},
				},
			},
		}

		card, err := parseV10(raw, "hash", testA2AEngine(t))
		if err != nil {
			t.Fatalf("parseV10: %v", err)
		}
		assertSecurityAlternatives(t, card.SecurityRequirements)
		if card.AuthMethod != "unknown" {
			t.Fatalf("ambiguous OR-of-AND auth method = %q, want unknown", card.AuthMethod)
		}
	})
}

func TestV10EmptySecurityRequirementIsAnonymousAlternative(t *testing.T) {
	for _, requirement := range []map[string]any{
		{},
		{"schemes": nil},
	} {
		raw := validV10Card()
		raw["securityRequirements"] = []any{requirement}

		card, err := parseV10(raw, "hash", testA2AEngine(t))
		if err != nil {
			t.Fatalf("parseV10: %v", err)
		}
		if !card.Conformant || !card.SecurityValid || card.AuthMethod != "none" {
			t.Fatalf("empty security requirement result = %+v", card)
		}
		if len(card.SecurityRequirements) != 1 ||
			!card.SecurityRequirements[0].Conformant ||
			len(card.SecurityRequirements[0].Schemes) != 0 {
			t.Fatalf("empty security alternative = %+v", card.SecurityRequirements)
		}

		nodes, _ := buildGraph(card, "scan")
		if len(nodes) == 0 || nodes[0].Properties["auth_method"] != "none" ||
			nodes[0].Properties["auth_evidence"] != "declared_security_scheme" {
			t.Fatalf("anonymous declaration graph properties = %+v", nodes)
		}
	}
}

func TestV10EmptySkillSecurityRequirementPreservesAttackSurface(t *testing.T) {
	raw := validV10Card()
	skills, ok := raw["skills"].([]any)
	if !ok || len(skills) != 1 {
		t.Fatal("valid v1 fixture has no skill")
	}
	skill, ok := skills[0].(map[string]any)
	if !ok {
		t.Fatal("valid v1 fixture skill is not an object")
	}
	skill["securityRequirements"] = []any{map[string]any{}}

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if len(card.Skills) != 1 || !card.Skills[0].Conformant ||
		len(card.Skills[0].SecurityRequirements) != 1 ||
		len(card.Skills[0].SecurityRequirements[0].Schemes) != 0 {
		t.Fatalf("anonymous skill requirement = %+v", card.Skills)
	}
	_, edges := buildGraph(card, "scan")
	var advertised bool
	for _, edge := range edges {
		if edge.Kind == "ADVERTISES_SKILL" {
			advertised = true
		}
	}
	if !advertised {
		t.Fatalf("anonymous conformant skill lost ADVERTISES_SKILL: %+v", edges)
	}
}

func TestV10AnonymousOrAuthenticatedAlternativesRemainAmbiguous(t *testing.T) {
	raw := validV10Card()
	raw["securitySchemes"] = map[string]any{
		"bearer": map[string]any{
			"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
		},
	}
	raw["securityRequirements"] = []any{
		map[string]any{},
		map[string]any{"schemes": map[string]any{
			"bearer": map[string]any{"list": []any{}},
		}},
	}

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if !card.Conformant || !card.SecurityValid ||
		len(card.SecurityRequirements) != 2 ||
		len(card.SecurityRequirements[0].Schemes) != 0 ||
		card.AuthMethod != "unknown" {
		t.Fatalf("anonymous-or-bearer alternatives = %+v", card)
	}
}

func TestV10SecurityRequirementRejectsNonObjectSchemes(t *testing.T) {
	raw := validV10Card()
	raw["securityRequirements"] = []any{
		map[string]any{"schemes": []any{}},
	}

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if card.Conformant || card.SecurityValid ||
		!containsString(card.ConformanceErrors, "securityRequirements[0].schemes: must be an object") {
		t.Fatalf("non-object schemes accepted: %+v", card)
	}
}

func TestV10SecurityRequirementAcceptsNullStringListAsEmptyScopes(t *testing.T) {
	raw := validV10Card()
	raw["securitySchemes"] = map[string]any{
		"bearer": map[string]any{
			"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
		},
	}
	raw["securityRequirements"] = []any{
		map[string]any{"schemes": map[string]any{
			"bearer": map[string]any{"list": nil},
		}},
	}

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if !card.Conformant || !card.SecurityValid || card.AuthMethod != "bearer" ||
		len(card.SecurityRequirements) != 1 ||
		len(card.SecurityRequirements[0].Schemes) != 1 ||
		len(card.SecurityRequirements[0].Schemes[0].Scopes) != 0 {
		t.Fatalf("null StringList scopes = %+v", card)
	}
}

func TestSkillOptionalRepeatedFieldsEnforceProtoJSONShape(t *testing.T) {
	raw := validV10Card()
	skills, ok := raw["skills"].([]any)
	if !ok || len(skills) != 1 {
		t.Fatal("valid v1 fixture has no skill")
	}
	skill, ok := skills[0].(map[string]any)
	if !ok {
		t.Fatal("valid v1 fixture skill is not an object")
	}
	skill["examples"] = map[string]any{}
	skill["inputModes"] = "application/json"
	skill["outputModes"] = true

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if len(card.Skills) != 1 || card.Skills[0].Conformant {
		t.Fatalf("malformed optional repeated fields accepted: %+v", card.Skills)
	}
	for _, field := range []string{"examples", "inputModes", "outputModes"} {
		if !containsString(
			card.Skills[0].ConformanceErrors,
			"skills[0]."+field+": must be an array",
		) {
			t.Errorf("missing %s type error: %v", field, card.Skills[0].ConformanceErrors)
		}
	}
	_, edges := buildGraph(card, "scan")
	for _, edge := range edges {
		if edge.Kind == "ADVERTISES_SKILL" {
			t.Fatalf("malformed skill emitted ADVERTISES_SKILL: %+v", edge)
		}
	}

	for _, field := range []string{"examples", "inputModes", "outputModes"} {
		skill[field] = nil
	}
	card, err = parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10 with null repeated fields: %v", err)
	}
	if len(card.Skills) != 1 || !card.Skills[0].Conformant {
		t.Fatalf("ProtoJSON null optional repeated fields rejected: %+v", card.Skills)
	}
}

func TestV10ProtoJSONNullSignaturesEmitUnsignedFindingState(t *testing.T) {
	raw := validV10Card()
	raw["signatures"] = nil

	card, err := ParseAgentCard(
		context.Background(),
		&RawCard{Parsed: raw, Version: "v1.0", CardHash: "hash"},
		testA2AEngine(t),
		VerifyOptions{},
	)
	if err != nil {
		t.Fatalf("ParseAgentCard: %v", err)
	}
	if !card.Conformant || card.IsSigned || card.SignatureStatus != SigStatusUnsigned {
		t.Fatalf("ProtoJSON null signatures = %+v", card)
	}

	nodes, _ := buildGraph(card, "scan")
	for _, node := range nodes {
		if len(node.Kinds) == 0 || node.Kinds[0] != "A2AAgent" {
			continue
		}
		if node.Properties["signature_verification_status"] != SigStatusUnsigned ||
			node.Properties["is_signed"] != false {
			t.Fatalf("null signatures do not emit unsigned-card query state: %+v", node.Properties)
		}
		return
	}
	t.Fatal("A2AAgent node not emitted")
}

func TestV10NonNullWrongShapedSignaturesRemainMalformed(t *testing.T) {
	raw := validV10Card()
	raw["signatures"] = "not-an-array"

	card, err := ParseAgentCard(
		context.Background(),
		&RawCard{Parsed: raw, Version: "v1.0", CardHash: "hash"},
		testA2AEngine(t),
		VerifyOptions{},
	)
	if err != nil {
		t.Fatalf("ParseAgentCard: %v", err)
	}
	if card.Conformant || !card.IsSigned || card.SignatureStatus != SigStatusMalformed ||
		!containsString(card.ConformanceErrors, "signatures: must be an array") {
		t.Fatalf("wrong-shaped signatures = %+v", card)
	}
}

func TestDeclaredOnlySecuritySchemesRemainInactive(t *testing.T) {
	raw := validV10Card()
	raw["securitySchemes"] = map[string]any{
		"bearer": map[string]any{
			"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
		},
	}
	delete(raw, "securityRequirements")

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	if card.AuthMethod != "unknown" {
		t.Fatalf("declared-only auth method = %q, want unknown", card.AuthMethod)
	}
	_, edges := buildGraph(card, "scan")
	for _, edge := range edges {
		if edge.Kind == "AUTHENTICATES_WITH" {
			t.Fatalf("declared-only scheme emitted functional auth edge: %+v", edge)
		}
	}
}

func TestBuildGraphQualifiesFunctionalEdges(t *testing.T) {
	raw := validV10Card()
	raw["supportedInterfaces"] = []any{
		map[string]any{
			"url":             "",
			"protocolBinding": "JSONRPC",
			"protocolVersion": "1.0",
		},
	}
	raw["skills"] = []any{
		map[string]any{
			"id":          "bad-skill",
			"name":        "BadSkill",
			"description": "Missing required tags",
		},
	}
	raw["securitySchemes"] = map[string]any{
		"bearer": map[string]any{
			"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
		},
	}
	raw["securityRequirements"] = []any{
		map[string]any{
			"schemes": map[string]any{"missing": map[string]any{"list": []any{}}},
		},
	}

	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	card.URL = "https://observed.example"
	nodes, edges := buildGraph(card, "scan")
	if len(nodes) < 2 {
		t.Fatalf("nonconformant card/skill observations were dropped: %+v", nodes)
	}
	for _, edge := range edges {
		switch edge.Kind {
		case "ADVERTISES_SKILL", "RUNS_ON", "AUTHENTICATES_WITH":
			t.Fatalf("invalid fact emitted functional edge: %+v", edge)
		}
	}
}

func TestBuildGraphExportsVersionedConformanceAndRequirements(t *testing.T) {
	raw := validV10Card()
	raw["securitySchemes"] = map[string]any{
		"bearer": map[string]any{
			"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
		},
	}
	raw["securityRequirements"] = []any{
		map[string]any{
			"schemes": map[string]any{
				"bearer": map[string]any{"list": []any{"agent.read"}},
			},
		},
	}
	card, err := parseV10(raw, "hash", testA2AEngine(t))
	if err != nil {
		t.Fatalf("parseV10: %v", err)
	}
	nodes, _ := buildGraph(card, "scan")
	if len(nodes) == 0 {
		t.Fatal("missing A2AAgent node")
	}
	properties := nodes[0].Properties
	if properties["card_schema_version"] != "v1.0.1" ||
		properties["card_conformant"] != true {
		t.Fatalf("versioned conformance properties = %+v", properties)
	}
	interfaces, ok := properties["interfaces"].([]map[string]any)
	if !ok || len(interfaces) != 1 || interfaces[0]["preferred"] != true {
		t.Fatalf("ordered interface properties = %#v", properties["interfaces"])
	}
	requirements, ok := properties["security_requirements"].([]map[string]any)
	if !ok || len(requirements) != 1 {
		t.Fatalf("security requirement properties = %#v", properties["security_requirements"])
	}
	schemes, ok := requirements[0]["schemes"].([]map[string]any)
	if !ok || len(schemes) != 1 ||
		!reflect.DeepEqual(schemes[0]["scopes"], []string{"agent.read"}) {
		t.Fatalf("security requirement scopes = %#v", requirements)
	}
}

func assertSecurityAlternatives(t *testing.T, got []SecurityRequirement) {
	t.Helper()
	if len(got) != 2 {
		t.Fatalf("security alternatives = %+v", got)
	}
	if len(got[0].Schemes) != 1 ||
		got[0].Schemes[0].Name != "oauth" ||
		!reflect.DeepEqual(got[0].Schemes[0].Scopes, []string{"read", "write"}) {
		t.Fatalf("first OR alternative = %+v", got[0])
	}
	if len(got[1].Schemes) != 2 {
		t.Fatalf("second OR alternative did not preserve AND: %+v", got[1])
	}
	names := map[string]bool{}
	for _, scheme := range got[1].Schemes {
		names[scheme.Name] = true
	}
	if !names["api"] || !names["mtls"] {
		t.Fatalf("second OR alternative = %+v", got[1])
	}
}

func validV030Card() map[string]any {
	return map[string]any{
		"name":               "Legacy Agent",
		"description":        "A conformant v0.3 agent",
		"url":                "https://legacy.example/a2a",
		"version":            "1.0.0",
		"protocolVersion":    "0.3.0",
		"preferredTransport": "JSONRPC",
		"capabilities":       map[string]any{},
		"defaultInputModes":  []any{"application/json"},
		"defaultOutputModes": []any{"application/json"},
		"skills": []any{
			map[string]any{
				"id":          "summarize",
				"name":        "Summarize",
				"description": "Summarizes input",
				"tags":        []any{"summary"},
			},
		},
	}
}

func validV10Card() map[string]any {
	return map[string]any{
		"name":        "V1 Agent",
		"description": "A conformant v1 agent",
		"supportedInterfaces": []any{
			map[string]any{
				"url":             "https://agent.example/a2a",
				"protocolBinding": "JSONRPC",
				"protocolVersion": "1.0",
			},
		},
		"version":            "1.0.0",
		"capabilities":       map[string]any{},
		"defaultInputModes":  []any{"application/json"},
		"defaultOutputModes": []any{"application/json"},
		"skills": []any{
			map[string]any{
				"id":          "summarize",
				"name":        "Summarize",
				"description": "Summarizes input",
				"tags":        []any{"summary"},
			},
		},
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

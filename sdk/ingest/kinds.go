package ingest

// AllowedNodeKinds are the 23 collector-produced node kinds accepted in ingest
// input. The first 12 are the v0.1 set; the next 8 are per-service AI-service
// kinds added in v0.2; AIService is the multi-label umbrella every per-service
// node also carries; AIModel is the v0.3 model-artifact kind; and
// ExtractedTrainingSignal is the v0.5 extraction-output kind.
var AllowedNodeKinds = map[string]bool{
	"MCPServer":               true,
	"MCPTool":                 true,
	"MCPResource":             true,
	"MCPPrompt":               true,
	"A2AAgent":                true,
	"A2ASkill":                true,
	"AgentInstance":           true,
	"Identity":                true,
	"Credential":              true,
	"Host":                    true,
	"ConfigFile":              true,
	"InstructionFile":         true,
	"OllamaInstance":          true,
	"VLLMInstance":            true,
	"QdrantInstance":          true,
	"MLflowServer":            true,
	"LiteLLMGateway":          true,
	"JupyterServer":           true,
	"LangServeApp":            true,
	"OpenWebUIInstance":       true,
	"AIService":               true,
	"AIModel":                 true,
	"ExtractedTrainingSignal": true,
}

// PublicNodeLabels is the ordered set of node labels exposed by inventory
// endpoints. Concrete AI-service labels precede the AIService umbrella so a
// multi-label node is counted under its concrete kind. Internal labels such as
// SchemaVersion are intentionally absent.
var PublicNodeLabels = []string{
	"MCPServer", "MCPTool", "MCPResource", "MCPPrompt",
	"A2AAgent", "A2ASkill", "AgentInstance",
	"Identity", "Credential", "Host",
	"ConfigFile", "InstructionFile",
	"OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
	"LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance",
	"AIModel", "ExtractedTrainingSignal", "AIService",
}

// AllNodeLabels includes all collector-produced node labels for Neo4j schema
// operations. Schema initialization skips labels in UmbrellaLabels when
// creating uniqueness constraints.
var AllNodeLabels = []string{
	"MCPServer", "MCPTool", "MCPResource", "MCPPrompt",
	"A2AAgent", "A2ASkill", "AgentInstance",
	"Identity", "Credential", "Host",
	"ConfigFile", "InstructionFile",
	"OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
	"LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance",
	"AIService", "AIModel", "ExtractedTrainingSignal",
}

// UmbrellaLabels are labels that nodes carry as a multi-label *companion* to a
// per-kind label rather than as their primary identity. The schema-init loop
// in server/internal/graph/schema.go MUST skip these when creating
// `objectid IS UNIQUE` constraints — every per-service node also carries
// :AIService, so a uniqueness constraint on the umbrella would falsely
// collide between distinct services that happen to share an objectid string
// across different per-kind hash inputs.
var UmbrellaLabels = map[string]bool{
	"AIService": true,
}

// UmbrellaCompanions enumerates the only valid public multi-label tuples.
// Every key is a concrete kind that owns object identity; values are optional
// query-convenience labels that may accompany it.
var UmbrellaCompanions = map[string]map[string]bool{
	"OllamaInstance":    {"AIService": true},
	"VLLMInstance":      {"AIService": true},
	"QdrantInstance":    {"AIService": true},
	"MLflowServer":      {"AIService": true},
	"LiteLLMGateway":    {"AIService": true},
	"JupyterServer":     {"AIService": true},
	"LangServeApp":      {"AIService": true},
	"OpenWebUIInstance": {"AIService": true},
}

// ConcreteNodeKind returns the sole identity-owning kind in a valid node-kind
// tuple. Invalid tuples return the empty string.
func ConcreteNodeKind(kinds []string) string {
	if len(kinds) == 0 {
		return ""
	}
	seen := make(map[string]bool, len(kinds))
	concrete := ""
	for _, kind := range kinds {
		if !AllowedNodeKinds[kind] || seen[kind] {
			return ""
		}
		seen[kind] = true
		if UmbrellaLabels[kind] {
			continue
		}
		if concrete != "" {
			return ""
		}
		concrete = kind
	}
	if concrete == "" || kinds[0] != concrete {
		return ""
	}
	for _, kind := range kinds[1:] {
		if !UmbrellaCompanions[concrete][kind] {
			return ""
		}
	}
	return concrete
}

// RawEdgeKinds are the 20 collector-produced edge kinds accepted in ingest
// input. EXPOSES is reserved in v0.2 for v0.3 fingerprinters; EXPOSES_CREDENTIAL
// is emitted by the v0.2 LiteLLM Looter; PROVIDES_MODEL is emitted by the v0.3
// Ollama Looter; EXTRACTED_FROM is emitted by the v0.5 embedding-inversion
// Extractor (AIModel → ExtractedTrainingSignal); INGESTS_UNTRUSTED is emitted by
// the MCP Collector for tools whose rule-derived source_trust is untrusted;
// CREDENTIAL_REACH_VERIFIED and PUBLIC_ACCESS_OBSERVED are emitted by the
// campaign runner's differential credential-reach scenario as raw supporting
// evidence (AgentInstance→MCPResource and MCPServer→MCPResource respectively).
var RawEdgeKinds = map[string]bool{
	"TRUSTS_SERVER":             true,
	"PROVIDES_TOOL":             true,
	"PROVIDES_RESOURCE":         true,
	"PROVIDES_PROMPT":           true,
	"ADVERTISES_SKILL":          true,
	"DELEGATES_TO":              true,
	"AUTHENTICATES_WITH":        true,
	"USES_CREDENTIAL":           true,
	"RUNS_ON":                   true,
	"CONFIGURED_IN":             true,
	"HAS_ENV_VAR":               true,
	"LOADS_INSTRUCTIONS":        true,
	"SAME_AUTH_DOMAIN":          true,
	"EXPOSES":                   true,
	"EXPOSES_CREDENTIAL":        true,
	"PROVIDES_MODEL":            true,
	"EXTRACTED_FROM":            true,
	"INGESTS_UNTRUSTED":         true,
	"CREDENTIAL_REACH_VERIFIED": true,
	"PUBLIC_ACCESS_OBSERVED":    true,
}

// AllowedEdgeKinds includes all 32 edge kinds (20 raw + 12 composite) for Neo4j writer dispatch.
var AllowedEdgeKinds = map[string]bool{
	// Raw (collector-produced)
	"TRUSTS_SERVER":             true,
	"PROVIDES_TOOL":             true,
	"PROVIDES_RESOURCE":         true,
	"PROVIDES_PROMPT":           true,
	"ADVERTISES_SKILL":          true,
	"DELEGATES_TO":              true,
	"AUTHENTICATES_WITH":        true,
	"USES_CREDENTIAL":           true,
	"RUNS_ON":                   true,
	"CONFIGURED_IN":             true,
	"HAS_ENV_VAR":               true,
	"LOADS_INSTRUCTIONS":        true,
	"SAME_AUTH_DOMAIN":          true,
	"EXPOSES":                   true,
	"EXPOSES_CREDENTIAL":        true,
	"PROVIDES_MODEL":            true,
	"EXTRACTED_FROM":            true,
	"INGESTS_UNTRUSTED":         true,
	"CREDENTIAL_REACH_VERIFIED": true,
	"PUBLIC_ACCESS_OBSERVED":    true,
	// Composite (post-processor produced)
	"HAS_ACCESS_TO":         true,
	"CAN_EXECUTE":           true,
	"CAN_REACH":             true,
	"CAN_EXFILTRATE_VIA":    true,
	"SHADOWS":               true,
	"POISONED_DESCRIPTION":  true,
	"CAN_IMPERSONATE":       true,
	"POISONED_INSTRUCTIONS": true,
	"CONFUSED_DEPUTY":       true,
	"TAINTS":                true,
	"IFC_VIOLATION":         true,
	"POISONS_CONTEXT":       true,
}

// AllowedCollectors are the valid collector identifiers in ingest meta.
var AllowedCollectors = map[string]bool{
	"mcp":    true,
	"a2a":    true,
	"config": true,
	"scan":   true,
}

// EdgeEndpoints defines the expected source and target node kinds for an edge kind.
type EdgeEndpoints struct {
	SourceKinds []string
	TargetKinds []string
}

// EdgeKindEndpoints maps each edge kind to its expected source/target node labels.
var EdgeKindEndpoints = map[string]EdgeEndpoints{
	"TRUSTS_SERVER":         {SourceKinds: []string{"AgentInstance"}, TargetKinds: []string{"MCPServer"}},
	"PROVIDES_TOOL":         {SourceKinds: []string{"MCPServer"}, TargetKinds: []string{"MCPTool"}},
	"PROVIDES_RESOURCE":     {SourceKinds: []string{"MCPServer", "JupyterServer", "MLflowServer", "QdrantInstance"}, TargetKinds: []string{"MCPResource"}},
	"PROVIDES_PROMPT":       {SourceKinds: []string{"MCPServer"}, TargetKinds: []string{"MCPPrompt"}},
	"ADVERTISES_SKILL":      {SourceKinds: []string{"A2AAgent"}, TargetKinds: []string{"A2ASkill"}},
	"DELEGATES_TO":          {SourceKinds: []string{"A2AAgent"}, TargetKinds: []string{"A2AAgent"}},
	"AUTHENTICATES_WITH":    {SourceKinds: []string{"MCPServer", "A2AAgent"}, TargetKinds: []string{"Identity"}},
	"USES_CREDENTIAL":       {SourceKinds: []string{"Identity"}, TargetKinds: []string{"Credential"}},
	"RUNS_ON":               {SourceKinds: []string{"MCPServer", "A2AAgent"}, TargetKinds: []string{"Host"}},
	"CONFIGURED_IN":         {SourceKinds: []string{"MCPServer"}, TargetKinds: []string{"ConfigFile"}},
	"HAS_ENV_VAR":           {SourceKinds: []string{"MCPServer"}, TargetKinds: []string{"Credential"}},
	"LOADS_INSTRUCTIONS":    {SourceKinds: []string{"AgentInstance"}, TargetKinds: []string{"InstructionFile"}},
	"SAME_AUTH_DOMAIN":      {SourceKinds: []string{"A2AAgent"}, TargetKinds: []string{"A2AAgent"}},
	"HAS_ACCESS_TO":         {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPResource"}},
	"CAN_EXECUTE":           {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"Host"}},
	"CAN_REACH":             {SourceKinds: []string{"AgentInstance", "A2AAgent"}, TargetKinds: []string{"MCPResource", "Credential"}},
	"CAN_EXFILTRATE_VIA":    {SourceKinds: []string{"AgentInstance"}, TargetKinds: []string{"MCPTool"}},
	"SHADOWS":               {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"POISONED_DESCRIPTION":  {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"CAN_IMPERSONATE":       {SourceKinds: []string{"A2AAgent"}, TargetKinds: []string{"A2AAgent"}},
	"POISONED_INSTRUCTIONS": {SourceKinds: []string{"InstructionFile"}, TargetKinds: []string{"InstructionFile"}},
	"EXPOSES":               {SourceKinds: []string{"AIService", "OpenWebUIInstance"}, TargetKinds: []string{"AIService", "OllamaInstance"}},
	"EXPOSES_CREDENTIAL":    {SourceKinds: []string{"AIService"}, TargetKinds: []string{"Credential"}},
	"PROVIDES_MODEL":        {SourceKinds: []string{"OllamaInstance"}, TargetKinds: []string{"AIModel"}},
	"EXTRACTED_FROM":        {SourceKinds: []string{"AIModel"}, TargetKinds: []string{"ExtractedTrainingSignal"}},
	"INGESTS_UNTRUSTED":     {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPResource"}},
	// campaign-runner verification evidence. CREDENTIAL_REACH_VERIFIED
	// records per-agent campaign verification evidence for a credential-gated
	// read (AgentInstance→MCPResource). It does not claim observed agent
	// invocation. PUBLIC_ACCESS_OBSERVED
	// records an anonymous read of a resource (MCPServer→MCPResource) — a fact,
	// not an auto-finding.
	"CREDENTIAL_REACH_VERIFIED": {SourceKinds: []string{"AgentInstance"}, TargetKinds: []string{"MCPResource"}},
	"PUBLIC_ACCESS_OBSERVED":    {SourceKinds: []string{"MCPServer"}, TargetKinds: []string{"MCPResource"}},
	"CONFUSED_DEPUTY":           {SourceKinds: []string{"A2AAgent"}, TargetKinds: []string{"A2AAgent"}},
	"TAINTS":                    {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"IFC_VIOLATION":             {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"POISONS_CONTEXT":           {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
}

// endpointKindAllowed reports whether kind is a member of allowed.
func endpointKindAllowed(allowed []string, kind string) bool {
	for _, k := range allowed {
		if k == kind {
			return true
		}
	}
	return false
}

// SourceKindAllowed reports whether sourceKind is a semantically valid source
// label for edgeKind per the EdgeKindEndpoints registry. Missing registry
// entries fail closed because ingest accepts only the exhaustive raw-edge
// registry. Callers should only pass a non-empty sourceKind.
func SourceKindAllowed(edgeKind, sourceKind string) bool {
	ep, ok := EdgeKindEndpoints[edgeKind]
	if !ok {
		return false
	}
	return endpointKindAllowed(ep.SourceKinds, sourceKind)
}

// TargetKindAllowed reports whether targetKind is a semantically valid target
// label for edgeKind per the EdgeKindEndpoints registry. See SourceKindAllowed.
func TargetKindAllowed(edgeKind, targetKind string) bool {
	ep, ok := EdgeKindEndpoints[edgeKind]
	if !ok {
		return false
	}
	return endpointKindAllowed(ep.TargetKinds, targetKind)
}

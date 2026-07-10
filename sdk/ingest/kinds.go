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

// AllNodeLabels includes all 25 node labels (23 collector + 2 synthetic) for
// Neo4j schema operations. Schema-init logic skips labels in UmbrellaLabels
// when creating uniqueness constraints — see UmbrellaLabels for the why.
var AllNodeLabels = []string{
	"MCPServer", "MCPTool", "MCPResource", "MCPPrompt",
	"A2AAgent", "A2ASkill", "AgentInstance",
	"Identity", "Credential", "Host",
	"ConfigFile", "InstructionFile",
	"OllamaInstance", "VLLMInstance", "QdrantInstance", "MLflowServer",
	"LiteLLMGateway", "JupyterServer", "LangServeApp", "OpenWebUIInstance",
	"AIService", "AIModel", "ExtractedTrainingSignal",
	"ResourceGroup", "TrustZone",
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

// RawEdgeKinds are the 18 collector-produced edge kinds accepted in ingest
// input. EXPOSES is reserved in v0.2 for v0.3 fingerprinters; EXPOSES_CREDENTIAL
// is emitted by the v0.2 LiteLLM Looter; PROVIDES_MODEL is emitted by the v0.3
// Ollama Looter; EXTRACTED_FROM is emitted by the v0.5 embedding-inversion
// Extractor (AIModel → ExtractedTrainingSignal); INGESTS_UNTRUSTED is emitted by
// the MCP Collector for tools whose rule-derived source_trust is untrusted.
var RawEdgeKinds = map[string]bool{
	"TRUSTS_SERVER":      true,
	"PROVIDES_TOOL":      true,
	"PROVIDES_RESOURCE":  true,
	"PROVIDES_PROMPT":    true,
	"ADVERTISES_SKILL":   true,
	"DELEGATES_TO":       true,
	"AUTHENTICATES_WITH": true,
	"USES_CREDENTIAL":    true,
	"RUNS_ON":            true,
	"CONFIGURED_IN":      true,
	"HAS_ENV_VAR":        true,
	"LOADS_INSTRUCTIONS": true,
	"SAME_AUTH_DOMAIN":   true,
	"EXPOSES":            true,
	"EXPOSES_CREDENTIAL": true,
	"PROVIDES_MODEL":     true,
	"EXTRACTED_FROM":     true,
	"INGESTS_UNTRUSTED":  true,
}

// AllowedEdgeKinds includes all 30 edge kinds (18 raw + 12 composite) for Neo4j writer dispatch.
var AllowedEdgeKinds = map[string]bool{
	// Raw (collector-produced)
	"TRUSTS_SERVER":      true,
	"PROVIDES_TOOL":      true,
	"PROVIDES_RESOURCE":  true,
	"PROVIDES_PROMPT":    true,
	"ADVERTISES_SKILL":   true,
	"DELEGATES_TO":       true,
	"AUTHENTICATES_WITH": true,
	"USES_CREDENTIAL":    true,
	"RUNS_ON":            true,
	"CONFIGURED_IN":      true,
	"HAS_ENV_VAR":        true,
	"LOADS_INSTRUCTIONS": true,
	"SAME_AUTH_DOMAIN":   true,
	"EXPOSES":            true,
	"EXPOSES_CREDENTIAL": true,
	"PROVIDES_MODEL":     true,
	"EXTRACTED_FROM":     true,
	"INGESTS_UNTRUSTED":  true,
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
	"CAN_REACH":             {SourceKinds: []string{"AgentInstance", "A2AAgent"}, TargetKinds: []string{"MCPResource"}},
	"CAN_EXFILTRATE_VIA":    {SourceKinds: []string{"AgentInstance"}, TargetKinds: []string{"MCPTool"}},
	"SHADOWS":               {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"POISONED_DESCRIPTION":  {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"CAN_IMPERSONATE":       {SourceKinds: []string{"A2AAgent"}, TargetKinds: []string{"A2AAgent"}},
	"POISONED_INSTRUCTIONS": {SourceKinds: []string{"InstructionFile"}, TargetKinds: []string{"InstructionFile"}},
	"EXPOSES":               {SourceKinds: []string{"AIService"}, TargetKinds: []string{"AIService"}},
	"EXPOSES_CREDENTIAL":    {SourceKinds: []string{"AIService"}, TargetKinds: []string{"Credential"}},
	"PROVIDES_MODEL":        {SourceKinds: []string{"OllamaInstance"}, TargetKinds: []string{"AIModel"}},
	"EXTRACTED_FROM":        {SourceKinds: []string{"AIModel"}, TargetKinds: []string{"ExtractedTrainingSignal"}},
	"INGESTS_UNTRUSTED":     {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPResource"}},
	"CONFUSED_DEPUTY":       {SourceKinds: []string{"A2AAgent"}, TargetKinds: []string{"A2AAgent"}},
	"TAINTS":                {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"IFC_VIOLATION":         {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
	"POISONS_CONTEXT":       {SourceKinds: []string{"MCPTool"}, TargetKinds: []string{"MCPTool"}},
}

// ResolveEdgeEndpoints returns the source and target node kinds for an edge,
// using explicit values when set, falling back to the EdgeKindEndpoints registry.
func ResolveEdgeEndpoints(kind, sourceKind, targetKind string) (string, string) {
	if sourceKind != "" && targetKind != "" {
		return sourceKind, targetKind
	}
	ep, ok := EdgeKindEndpoints[kind]
	if !ok {
		return sourceKind, targetKind
	}
	if sourceKind == "" && len(ep.SourceKinds) > 0 {
		sourceKind = ep.SourceKinds[0]
	}
	if targetKind == "" && len(ep.TargetKinds) > 0 {
		targetKind = ep.TargetKinds[0]
	}
	return sourceKind, targetKind
}

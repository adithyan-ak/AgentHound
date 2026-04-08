package model

// AllowedNodeKinds are the 12 collector-produced node kinds accepted in ingest input.
var AllowedNodeKinds = map[string]bool{
	"MCPServer":       true,
	"MCPTool":         true,
	"MCPResource":     true,
	"MCPPrompt":       true,
	"A2AAgent":        true,
	"A2ASkill":        true,
	"AgentInstance":   true,
	"Identity":        true,
	"Credential":      true,
	"Host":            true,
	"ConfigFile":      true,
	"InstructionFile": true,
}

// AllNodeLabels includes all 14 node labels (12 collector + 2 synthetic) for Neo4j schema constraints.
var AllNodeLabels = []string{
	"MCPServer", "MCPTool", "MCPResource", "MCPPrompt",
	"A2AAgent", "A2ASkill", "AgentInstance",
	"Identity", "Credential", "Host",
	"ConfigFile", "InstructionFile",
	"ResourceGroup", "TrustZone",
}

// RawEdgeKinds are the 13 collector-produced edge kinds accepted in ingest input.
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
}

// AllowedEdgeKinds includes all 21 edge kinds (13 raw + 8 composite) for Neo4j writer dispatch.
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
	// Composite (post-processor produced)
	"HAS_ACCESS_TO":         true,
	"CAN_EXECUTE":           true,
	"CAN_REACH":             true,
	"CAN_EXFILTRATE_VIA":    true,
	"SHADOWS":               true,
	"POISONED_DESCRIPTION":  true,
	"CAN_IMPERSONATE":       true,
	"POISONED_INSTRUCTIONS": true,
}

// AllowedCollectors are the valid collector identifiers in ingest meta.
var AllowedCollectors = map[string]bool{
	"mcp":    true,
	"a2a":    true,
	"config": true,
}

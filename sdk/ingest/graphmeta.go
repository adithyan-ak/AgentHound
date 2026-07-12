package ingest

//go:generate go run github.com/adithyan-ak/agenthound/server/cmd/gengraphts

// This file is the canonical, language-neutral source of graph presentation
// semantics: what each node/edge kind means, which explorer lens it belongs
// to, and whether an edge is a collector-produced fact or a post-processor
// inference. The TypeScript registry consumed by the UI
// (server/ui/src/entities/graph/generated.ts) is generated from these tables
// by cmd/gengraphts, so Go and TypeScript can never drift.
//
// Endpoint metadata (allowed source/target kinds) lives in EdgeKindEndpoints
// in kinds.go; the generator emits it alongside the tables here.

// LensCategory is the explorer lens a graph edge is framed under. Values match
// the UI lens ids in features/explorer/model/lens-config.ts.
type LensCategory string

const (
	LensTopology      LensCategory = "topology"
	LensAttackSurface LensCategory = "attack-surface"
	LensCredentials   LensCategory = "credentials"
	LensPoisoning     LensCategory = "poisoning"
)

// AllLensCategories is the canonical ordered set of edge lens categories.
var AllLensCategories = []LensCategory{
	LensTopology, LensAttackSurface, LensCredentials, LensPoisoning,
}

// NodeKindMeta describes a node kind for presentation and generation.
type NodeKindMeta struct {
	Kind string
	// GroupLabel buckets kinds in the legend/explorer layout.
	GroupLabel string
	// CollectorProduced is true when a collector may emit this kind directly
	// (i.e. it is in AllowedNodeKinds). Synthetic/aggregate kinds are false.
	CollectorProduced bool
	// Umbrella is true for multi-label companion kinds (e.g. AIService) that
	// never carry their own uniqueness constraint.
	Umbrella bool
}

// EdgeKindMeta describes an edge kind for presentation and generation.
type EdgeKindMeta struct {
	Kind string
	// Description is the short relationship phrase ("Agent trusts MCP server").
	Description string
	// Lens is the explorer lens this edge is framed under.
	Lens LensCategory
	// Composite is true for post-processor-inferred edges (not raw facts).
	Composite bool
	// Directed is true when the edge has meaningful source→target orientation.
	Directed bool
}

// NodeKindMetadata is the ordered canonical node-kind table. Order follows
// AllNodeLabels so the generated union is stable.
var NodeKindMetadata = []NodeKindMeta{
	{Kind: "MCPServer", GroupLabel: "Servers", CollectorProduced: true},
	{Kind: "MCPTool", GroupLabel: "Tools & Skills", CollectorProduced: true},
	{Kind: "MCPResource", GroupLabel: "Resources", CollectorProduced: true},
	{Kind: "MCPPrompt", GroupLabel: "Tools & Skills", CollectorProduced: true},
	{Kind: "A2AAgent", GroupLabel: "Agents", CollectorProduced: true},
	{Kind: "A2ASkill", GroupLabel: "Tools & Skills", CollectorProduced: true},
	{Kind: "AgentInstance", GroupLabel: "Agents", CollectorProduced: true},
	{Kind: "Identity", GroupLabel: "Infra", CollectorProduced: true},
	{Kind: "Credential", GroupLabel: "Infra", CollectorProduced: true},
	{Kind: "Host", GroupLabel: "Infra", CollectorProduced: true},
	{Kind: "ConfigFile", GroupLabel: "Resources", CollectorProduced: true},
	{Kind: "InstructionFile", GroupLabel: "Resources", CollectorProduced: true},
	{Kind: "OllamaInstance", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "VLLMInstance", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "QdrantInstance", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "MLflowServer", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "LiteLLMGateway", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "JupyterServer", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "LangServeApp", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "OpenWebUIInstance", GroupLabel: "AI Services", CollectorProduced: true},
	{Kind: "AIService", GroupLabel: "AI Services", CollectorProduced: true, Umbrella: true},
	{Kind: "AIModel", GroupLabel: "AI Models", CollectorProduced: true},
	{Kind: "ExtractedTrainingSignal", GroupLabel: "AI Models", CollectorProduced: true},
}

// EdgeKindMetadata is the ordered canonical edge-kind table. Raw
// (collector-produced) kinds first, then composite (post-processor) kinds,
// matching the dispatch order in AllowedEdgeKinds.
var EdgeKindMetadata = []EdgeKindMeta{
	// Raw facts.
	{Kind: "TRUSTS_SERVER", Description: "Agent trusts MCP server", Lens: LensTopology, Directed: true},
	{Kind: "PROVIDES_TOOL", Description: "Server provides tool", Lens: LensTopology, Directed: true},
	{Kind: "PROVIDES_RESOURCE", Description: "Server provides resource", Lens: LensTopology, Directed: true},
	{Kind: "PROVIDES_PROMPT", Description: "Server provides prompt template", Lens: LensTopology, Directed: true},
	{Kind: "ADVERTISES_SKILL", Description: "A2A agent advertises skill", Lens: LensTopology, Directed: true},
	{Kind: "DELEGATES_TO", Description: "Agent delegates to agent", Lens: LensTopology, Directed: true},
	{Kind: "AUTHENTICATES_WITH", Description: "Authenticates with identity", Lens: LensCredentials, Directed: true},
	{Kind: "USES_CREDENTIAL", Description: "Identity uses credential", Lens: LensCredentials, Directed: true},
	{Kind: "RUNS_ON", Description: "Runs on host", Lens: LensTopology, Directed: true},
	{Kind: "CONFIGURED_IN", Description: "Configured in file", Lens: LensTopology, Directed: true},
	{Kind: "HAS_ENV_VAR", Description: "Has credential env var", Lens: LensCredentials, Directed: true},
	{Kind: "LOADS_INSTRUCTIONS", Description: "Loads instruction file", Lens: LensTopology, Directed: true},
	{Kind: "SAME_AUTH_DOMAIN", Description: "Shares auth domain", Lens: LensTopology, Directed: false},
	{Kind: "EXPOSES", Description: "Exposes AI service", Lens: LensTopology, Directed: true},
	{Kind: "EXPOSES_CREDENTIAL", Description: "Exposes credential material", Lens: LensCredentials, Directed: true},
	{Kind: "PROVIDES_MODEL", Description: "Serves model artifact", Lens: LensTopology, Directed: true},
	{Kind: "EXTRACTED_FROM", Description: "Extracted from model", Lens: LensTopology, Directed: true},
	{Kind: "INGESTS_UNTRUSTED", Description: "Ingests untrusted content", Lens: LensPoisoning, Directed: true},
	// Composite inferences.
	{Kind: "HAS_ACCESS_TO", Description: "Tool can access resource", Lens: LensAttackSurface, Composite: true, Directed: true},
	{Kind: "CAN_EXECUTE", Description: "Tool can execute on host", Lens: LensAttackSurface, Composite: true, Directed: true},
	{Kind: "CAN_REACH", Description: "Agent can reach resource", Lens: LensAttackSurface, Composite: true, Directed: true},
	{Kind: "CAN_REACH_CROSS_PROTOCOL", Description: "Agent can reach resource across protocols", Lens: LensAttackSurface, Composite: true, Directed: true},
	{Kind: "CAN_REACH_CREDENTIAL_CHAIN", Description: "Agent can reach upstream credential", Lens: LensCredentials, Composite: true, Directed: true},
	{Kind: "CAN_EXFILTRATE_VIA", Description: "Agent can exfiltrate via tool", Lens: LensAttackSurface, Composite: true, Directed: true},
	{Kind: "SHADOWS", Description: "Tool shadows another tool", Lens: LensPoisoning, Composite: true, Directed: true},
	{Kind: "POISONED_DESCRIPTION", Description: "Poisoned tool description", Lens: LensPoisoning, Composite: true, Directed: true},
	{Kind: "CAN_IMPERSONATE", Description: "Agent can impersonate agent", Lens: LensAttackSurface, Composite: true, Directed: true},
	{Kind: "POISONED_INSTRUCTIONS", Description: "Poisoned instruction file", Lens: LensPoisoning, Composite: true, Directed: true},
	{Kind: "CONFUSED_DEPUTY", Description: "Confused-deputy delegation", Lens: LensAttackSurface, Composite: true, Directed: true},
	{Kind: "TAINTS", Description: "Taints downstream tool", Lens: LensPoisoning, Composite: true, Directed: true},
	{Kind: "IFC_VIOLATION", Description: "Information-flow-control violation", Lens: LensPoisoning, Composite: true, Directed: true},
	{Kind: "POISONS_CONTEXT", Description: "Poisons agent context", Lens: LensPoisoning, Composite: true, Directed: true},
}

// nodeKindMetaIndex / edgeKindMetaIndex are lazily built lookup maps.
var (
	nodeKindMetaIndex map[string]NodeKindMeta
	edgeKindMetaIndex map[string]EdgeKindMeta
)

func init() {
	nodeKindMetaIndex = make(map[string]NodeKindMeta, len(NodeKindMetadata))
	for _, m := range NodeKindMetadata {
		nodeKindMetaIndex[m.Kind] = m
	}
	edgeKindMetaIndex = make(map[string]EdgeKindMeta, len(EdgeKindMetadata))
	for _, m := range EdgeKindMetadata {
		edgeKindMetaIndex[m.Kind] = m
	}
}

// NodeKindMetaFor returns the metadata for a node kind and whether it exists.
func NodeKindMetaFor(kind string) (NodeKindMeta, bool) {
	m, ok := nodeKindMetaIndex[kind]
	return m, ok
}

// EdgeKindMetaFor returns the metadata for an edge kind and whether it exists.
func EdgeKindMetaFor(kind string) (EdgeKindMeta, bool) {
	m, ok := edgeKindMetaIndex[kind]
	return m, ok
}

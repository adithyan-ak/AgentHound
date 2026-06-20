package prebuilt

import "sort"

// PreBuiltQuery defines a pre-built security query with metadata.
type PreBuiltQuery struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Cypher      string   `json:"-"`
	OWASPMap    []string `json:"owasp_map,omitempty"`
	ATLASMap    []string `json:"atlas_map,omitempty"`
}

// Registry maps query IDs to their definitions.
var Registry map[string]PreBuiltQuery

func init() {
	Registry = map[string]PreBuiltQuery{
		// Critical Paths
		"agents-shell-access": {
			ID:          "agents-shell-access",
			Name:        "Agents with Shell Access",
			Description: "Finds agents that can reach tools with shell or code execution capabilities.",
			Category:    "Critical Paths",
			Severity:    "critical",
			Cypher:      CypherAgentsShellAccess,
			OWASPMap:    []string{"MCP01", "ASI06"},
		},
		"shortest-to-database": {
			ID:          "shortest-to-database",
			Name:        "Shortest Path to Database",
			Description: "Finds the shortest path from any agent to database resources (postgres, mysql, mongodb, redis).",
			Category:    "Critical Paths",
			Severity:    "critical",
			Cypher:      CypherShortestToDatabase,
			OWASPMap:    []string{"MCP04", "ASI08"},
		},
		"cross-protocol-paths": {
			ID:          "cross-protocol-paths",
			Name:        "Cross-Protocol Attack Paths",
			Description: "Finds A2A-to-MCP cross-protocol attack paths that span protocol boundaries.",
			Category:    "Critical Paths",
			Severity:    "critical",
			Cypher:      CypherCrossProtocolPaths,
			OWASPMap:    []string{"MCP01", "ASI01", "ASI06"},
		},
		"exfiltration-routes": {
			ID:          "exfiltration-routes",
			Name:        "Data Exfiltration Routes",
			Description: "Finds agents that can reach sensitive data and have an outbound exfiltration channel.",
			Category:    "Critical Paths",
			Severity:    "critical",
			Cypher:      CypherExfiltrationRoutes,
			OWASPMap:    []string{"MCP04", "ASI08", "ASI10"},
			ATLASMap:    []string{"AML.T0086"},
		},
		"credential-chain": {
			ID:          "credential-chain",
			Name:        "Credential Chain Paths",
			Description: "Finds multi-hop paths from agents to resources that traverse credential boundaries.",
			Category:    "Critical Paths",
			Severity:    "critical",
			Cypher:      CypherCredentialChain,
			OWASPMap:    []string{"MCP03", "ASI04"},
		},
		"litellm-credential-leak": {
			ID:          "litellm-credential-leak",
			Name:        "LiteLLM Credential Leak",
			Description: "Finds upstream provider credentials reachable through a LiteLLM gateway whose master key was discovered in agent config (cross-collector value_hash join).",
			Category:    "Critical Paths",
			Severity:    "critical",
			Cypher:      CypherLitellmCredentialLeak,
			OWASPMap:    []string{"MCP03", "ASI04"},
		},

		// Vulnerabilities
		"poisoned-tools": {
			ID:          "poisoned-tools",
			Name:        "Poisoned Tool Descriptions",
			Description: "Finds tools with injection patterns in their descriptions that may manipulate agent behavior.",
			Category:    "Vulnerabilities",
			Severity:    "high",
			Cypher:      CypherPoisonedTools,
			OWASPMap:    []string{"MCP05", "ASI03"},
			ATLASMap:    []string{"AML.T0051", "AML.T0110"},
		},
		"tool-shadowing": {
			ID:          "tool-shadowing",
			Name:        "Cross-Server Tool Shadowing",
			Description: "Finds tools on different servers that shadow each other, potentially hijacking agent actions.",
			Category:    "Vulnerabilities",
			Severity:    "high",
			Cypher:      CypherToolShadowing,
			OWASPMap:    []string{"MCP05", "ASI03"},
			ATLASMap:    []string{"AML.T0110"},
		},
		"no-auth-servers": {
			ID:          "no-auth-servers",
			Name:        "Unauthenticated MCP Servers",
			Description: "Finds MCP servers with no authentication configured.",
			Category:    "Vulnerabilities",
			Severity:    "high",
			Cypher:      CypherNoAuthServers,
			OWASPMap:    []string{"MCP03", "ASI04"},
		},
		"no-auth-a2a": {
			ID:          "no-auth-a2a",
			Name:        "Unauthenticated A2A Agents",
			Description: "Finds A2A agents with no authentication configured.",
			Category:    "Vulnerabilities",
			Severity:    "high",
			Cypher:      CypherNoAuthA2A,
			OWASPMap:    []string{"MCP03", "ASI04"},
		},
		"rug-pull": {
			ID:          "rug-pull",
			Name:        "Tool Description Rug Pull",
			Description: "Finds tools whose description changed between scans, indicating potential rug pull attacks.",
			Category:    "Vulnerabilities",
			Severity:    "high",
			Cypher:      CypherRugPull,
			OWASPMap:    []string{"MCP05", "MCP09"},
			ATLASMap:    []string{"AML.T0110", "AML.T0010"},
		},

		// Supply Chain
		"unpinned-packages": {
			ID:          "unpinned-packages",
			Name:        "Unpinned MCP Server Packages",
			Description: "Finds MCP servers running unpinned packages, vulnerable to supply chain attacks.",
			Category:    "Supply Chain",
			Severity:    "medium",
			Cypher:      CypherUnpinnedPackages,
			OWASPMap:    []string{"MCP09", "ASI09"},
		},
		"instruction-poisoning": {
			ID:          "instruction-poisoning",
			Name:        "Poisoned Instruction Files",
			Description: "Finds instruction files with suspicious patterns that may manipulate agent behavior.",
			Category:    "Supply Chain",
			Severity:    "high",
			Cypher:      CypherInstructionPoisoning,
			OWASPMap:    []string{"MCP05", "ASI03"},
			ATLASMap:    []string{"AML.T0051"},
		},
		"unsigned-cards": {
			ID:          "unsigned-cards",
			Name:        "Unsigned A2A Agent Cards",
			Description: "Finds A2A agents whose agent cards lack cryptographic signatures.",
			Category:    "Supply Chain",
			Severity:    "medium",
			Cypher:      CypherUnsignedCards,
			OWASPMap:    []string{"MCP09", "ASI09"},
		},
		"high-entropy-secrets": {
			ID:          "high-entropy-secrets",
			Name:        "High-Entropy Secrets in Config",
			Description: "Finds credentials with high Shannon entropy, likely hardcoded secrets.",
			Category:    "Supply Chain",
			Severity:    "high",
			Cypher:      CypherHighEntropySecrets,
			OWASPMap:    []string{"MCP03", "ASI04"},
		},

		// Chokepoints
		"chokepoint-servers": {
			ID:          "chokepoint-servers",
			Name:        "Chokepoint Servers",
			Description: "Finds MCP servers trusted by multiple agents -- compromising one server impacts many agents.",
			Category:    "Chokepoints",
			Severity:    "medium",
			Cypher:      CypherChokepointServers,
			OWASPMap:    []string{"MCP01", "ASI06"},
		},
		"chokepoint-tools": {
			ID:          "chokepoint-tools",
			Name:        "Chokepoint Tools",
			Description: "Finds tools with access to many resources -- high blast radius if compromised.",
			Category:    "Chokepoints",
			Severity:    "medium",
			Cypher:      CypherChokepointTools,
			OWASPMap:    []string{"MCP01", "ASI06"},
		},

		// Combined
		"unpinned-shell": {
			ID:          "unpinned-shell",
			Name:        "Unpinned Packages with Shell Access",
			Description: "Finds unpinned MCP server packages that also have shell/code execution tools -- the highest-risk supply chain scenario.",
			Category:    "Combined",
			Severity:    "critical",
			Cypher:      CypherUnpinnedShell,
			OWASPMap:    []string{"MCP01", "MCP09", "ASI06", "ASI09"},
		},
		"tool-name-collision": {
			ID:          "tool-name-collision",
			Name:        "Cross-Server Tool Name Collisions",
			Description: "Finds tools on different servers that share a normalized name -- a malicious server can shadow a trusted tool by reusing its name.",
			Category:    "Vulnerabilities",
			Severity:    "high",
			Cypher:      CypherToolNameCollision,
			OWASPMap:    []string{"MCP05", "ASI03"},
			ATLASMap:    []string{"AML.T0110"},
		},
	}
}

// Get returns a pre-built query by ID. Returns false if not found.
func Get(id string) (PreBuiltQuery, bool) {
	q, ok := Registry[id]
	return q, ok
}

// List returns all pre-built queries sorted by category then ID.
func List() []PreBuiltQuery {
	queries := make([]PreBuiltQuery, 0, len(Registry))
	for _, q := range Registry {
		queries = append(queries, q)
	}
	sort.Slice(queries, func(i, j int) bool {
		if queries[i].Category != queries[j].Category {
			return queries[i].Category < queries[j].Category
		}
		return queries[i].ID < queries[j].ID
	})
	return queries
}

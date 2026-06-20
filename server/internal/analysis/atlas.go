package analysis

// ATLASTechniques is the single source of truth for the MITRE ATLAS techniques
// AgentHound maps findings to. IDs and titles are verbatim from MITRE ATLAS
// v4.5.0 (MITRE renamed several "ML"→"AI"; titles below are the current names).
var ATLASTechniques = map[string]string{
	"AML.T0051": "LLM Prompt Injection",
	"AML.T0110": "AI Agent Tool Poisoning",
	"AML.T0086": "Exfiltration via AI Agent Tool Invocation",
	"AML.T0024": "Exfiltration via AI Inference API",
	"AML.T0057": "LLM Data Leakage",
	"AML.T0020": "Poison Training Data",
	"AML.T0010": "AI Supply Chain Compromise",
}

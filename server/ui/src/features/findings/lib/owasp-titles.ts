export const OWASP_TITLES: Record<string, string> = {
  MCP01: "Excessive Agency",
  MCP02: "Insufficient Access Controls",
  MCP03: "Lack of Tool Guardrails",
  MCP04: "Tool Argument Injection",
  MCP05: "Prompt Injection via Tool Description",
  MCP06: "Lack of Monitoring/Logging",
  MCP07: "Insecure Plugin/Extension Trust",
  MCP08: "Lack of Rate Limiting",
  MCP09: "Insufficient Error Handling",
  MCP10: "Insecure Transport",
  ASI01: "Excessive Agency",
  ASI02: "Lack of Guardrails",
  ASI03: "Prompt Injection",
  ASI04: "Insecure Output Handling",
  ASI05: "Supply Chain Vulnerabilities",
  ASI06: "Insufficient Access Controls",
  ASI07: "Over-Reliance on AI Output",
  ASI08: "Data Leakage",
  ASI09: "Lack of Observability",
  ASI10: "Insufficient Monitoring",
};

// MITRE ATLAS technique titles. Source of truth is the Go map ATLASTechniques
// in server/internal/analysis/atlas.go (guarded server-side by atlas_test.go);
// keep these in sync with it.
export const ATLAS_TITLES: Record<string, string> = {
  "AML.T0051": "LLM Prompt Injection",
  "AML.T0110": "AI Agent Tool Poisoning",
  "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
  "AML.T0024": "Exfiltration via AI Inference API",
  "AML.T0057": "LLM Data Leakage",
  "AML.T0020": "Poison Training Data",
  "AML.T0010": "AI Supply Chain Compromise",
};

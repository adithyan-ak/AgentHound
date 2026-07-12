import { describe, expect, it } from "vitest";
import type { AttackPath, Finding } from "@entities/finding/model";
import {
  buildFindingsTableMarkdown,
  buildMarkdownReport,
} from "@features/findings/lib/copy-report";
import { EDGE_EXPLOIT } from "@entities/edge/semantics";

const mappedFinding: Finding = {
  id: "aaaaaaaaaaaaaaaa",
  severity: "high",
  category: "Prompt Injection",
  title: "Poisoned tool description",
  description: "Tool PoisonedTool has injection patterns in its description",
  edge_kind: "POISONED_DESCRIPTION",
  source_id: "tool-1",
  source_name: "PoisonedTool",
  source_kind: "MCPTool",
  target_id: "tool-1",
  target_name: "PoisonedTool",
  target_kind: "MCPTool",
  confidence: 1,
  variant: "default",
  evidence: { state: "observed_signal", detector: "mcp" },
  owasp_map: ["MCP05", "ASI03"],
  atlas_map: ["AML.T0051", "AML.T0110"],
};

describe("finding Markdown reports", () => {
  it("includes ATLAS mappings in the selected-findings table export", () => {
    const markdown = buildFindingsTableMarkdown([mappedFinding]);

    expect(markdown).toContain("| OWASP | MITRE ATLAS | Conf |");
    expect(markdown).toContain("MCP05, ASI03");
    expect(markdown).toContain("AML.T0051, AML.T0110");
  });

  it("includes ATLAS mappings in the finding-detail export", () => {
    const markdown = buildMarkdownReport(mappedFinding, null, [
      {
        step: 1,
        title: "Restrict channel",
        description: "Review the matched output capability.",
        edge_kind: "CAN_EXFILTRATE_VIA",
        source: { id: "agent-1", name: "Agent", kind: "AgentInstance" },
        target: { id: "tool-1", name: "PoisonedTool", kind: "MCPTool" },
        channels: ["file_write"],
      },
    ]);

    expect(markdown).toContain(
      "**References:** OWASP: MCP05, ASI03 | MITRE ATLAS: AML.T0051, AML.T0110",
    );
    expect(markdown).toContain(
      "Actors: AgentInstance Agent → MCPTool PoisonedTool | Channels: file_write",
    );
  });

  it("describes every exfiltration capability without claiming network-only evidence", () => {
    const detail = EDGE_EXPLOIT.CAN_EXFILTRATE_VIA?.detail ?? "";

    expect(detail).toContain("file_write");
    expect(detail).toContain("auto_fetch_render");
    expect(detail).toContain("allowlisted_proxy");
    expect(detail).not.toContain("has a tool with outbound network capability");
  });

  it("exports non-linear evidence as an exact graph without inventing hops", () => {
    const path: AttackPath = {
      nodes: [
        { id: "agent", kinds: ["AgentInstance"], properties: { name: "Agent" } },
        { id: "server", kinds: ["MCPServer"], properties: { name: "Server" } },
        { id: "tool", kinds: ["MCPTool"], properties: { name: "Tool" } },
      ],
      edges: [
        {
          source: "agent",
          target: "server",
          kind: "TRUSTS_SERVER",
          properties: { risk_weight: 0.1 },
          synthetic: false,
        },
        {
          source: "server",
          target: "tool",
          kind: "PROVIDES_TOOL",
          properties: {},
          synthetic: false,
        },
      ],
      shape: "branched",
      continuity: {
        state: "continuous",
        component_count: 1,
        missing_node_ids: [],
      },
      direction: "non_linear",
      completeness: { state: "complete", reasons: [] },
      cost: {
        state: "not_applicable",
        value: null,
        reasons: ["non_linear_evidence"],
        missing_weight_edge_indexes: [],
      },
      total_risk_weight: null,
    };

    const markdown = buildMarkdownReport(mappedFinding, path, []);
    expect(markdown).toContain("### Evidence Graph (2 relationships)");
    expect(markdown).not.toContain("### Attack Path");
    expect(markdown).toContain("Attack cost: not applicable");
    expect(markdown).toContain("Agent -[TRUSTS_SERVER]-> Server");
    expect(markdown).toContain("No generated recommendation is available");
  });
});

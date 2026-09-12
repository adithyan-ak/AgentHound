import { describe, expect, it } from "vitest";
import type { Finding } from "@entities/finding/model";
import { buildFindingsTableMarkdown, buildMarkdownReport } from "./copy-report";
import { formatFindingEvidenceState } from "./evidence-label";

describe("buildMarkdownReport proof", () => {
  it("includes structured access proof metadata", () => {
    const finding: Finding = {
      id: "aaaaaaaaaaaaaaaa",
      severity: "high",
      category: "Transitive Access",
      title: "Verified reach",
      description: "Credential-gated reach was verified.",
      edge_kind: "CAN_REACH",
      source_id: "agent",
      source_name: "Agent",
      source_kind: "AgentInstance",
      target_id: "resource",
      target_name: "Resource",
      target_kind: "MCPResource",
      confidence: 1,
      variant: "default",
      evidence: {
        state: "verified",
        channels: [],
        proof: {
          action: "credential_reach",
          action_id: "action-report",
          verified_at: "2026-07-13T12:00:00Z",
          proof_type: "differential_resource_read",
          outcome: "credential_required",
          control_stage: "initialize",
          control_status: "denied",
          control_resource_addressed: false,
          credential_stage: "resource_read",
          credential_status: "allowed",
          credential_resource_addressed: true,
          cleanup_status: "not_applicable",
        },
      },
      owasp_map: [],
      atlas_map: [],
    };
    const report = buildMarkdownReport(finding, null, []);
    expect(formatFindingEvidenceState(finding.evidence.state)).toBe("Verified During Scan");
    expect(report).toContain("Evidence: Verified During Scan");
    expect(buildFindingsTableMarkdown([finding])).toContain("| Verified During Scan |");
    expect(report).toContain("### Access Proof");
    expect(report).toContain("Action ID: action-report");
    expect(report).toContain("Control: initialize / denied / resource_addressed=false");
    expect(report).toContain("Credential: resource_read / allowed / resource_addressed=true");
    expect(report).toContain("Cleanup: not_applicable");
    expect(report).toContain("not observed agent invocation or downstream impact");
  });
});

describe("buildMarkdownReport destructive instruction path", () => {
  it("retains instruction evidence, endpoints, confidence, and relationship evidence", () => {
    const finding: Finding = {
      id: "bbbbbbbbbbbbbbbb",
      severity: "high",
      category: "Destructive Impact",
      title: "Inferred path to a server-declared destructive tool",
      description:
        "The annotation is untrusted, and AgentHound did not invoke the tool or observe an effect.",
      edge_kind: "POISONS_CONTEXT",
      source_id: "instruction",
      source_name: "/work/AGENTS.md",
      source_kind: "InstructionFile",
      target_id: "tool",
      target_name: "Delete records",
      target_kind: "MCPTool",
      confidence: 0.6,
      variant: "destructive_tool_sink",
      evidence: {
        state: "inferred",
        match_type: "mcp_annotation_destructive_hint",
        channels: [],
      },
      owasp_map: ["MCP05"],
      atlas_map: ["AML.T0051"],
    };
    const report = buildMarkdownReport(
      finding,
      {
        nodes: [
          { id: "agent", kinds: ["AgentInstance"], properties: { name: "Agent" } },
          { id: "instruction", kinds: ["InstructionFile"], properties: { name: "AGENTS.md" } },
          { id: "tool", kinds: ["MCPTool"], properties: { name: "Delete records" } },
        ],
        edges: [
          {
            source: "agent",
            target: "instruction",
            kind: "LOADS_INSTRUCTIONS",
            properties: {},
            synthetic: false,
          },
        ],
        shape: "linear",
        continuity: { state: "continuous", component_count: 1, missing_node_ids: [] },
        direction: "mixed",
        completeness: { state: "complete", reasons: [] },
        cost: {
          state: "incomplete",
          value: null,
          reasons: ["non_forward_evidence"],
          missing_weight_edge_indexes: [],
        },
        total_risk_weight: null,
      },
      [],
      undefined,
      {
        version: 1,
        verdict: "poisoning",
        scope: "exact_project",
        path: "/work/AGENTS.md",
        type: "agents.md",
        hash: "sha256:abc",
        size_bytes: 100,
        modified_at: "2026-08-20T12:00:00Z",
        total_signals: 1,
        truncated: false,
        signals: [
          {
            rule_id: "rule",
            label: "Rule",
            severity: "high",
            strength: "primary",
            raw_offset: 1,
            line: 4,
            column: 2,
            match: "ignore controls",
            context_before: "",
            context_after: "",
          },
        ],
      },
    );

    expect(report).toContain("Confidence: 60%");
    expect(report).toContain("**Source:** /work/AGENTS.md (InstructionFile)");
    expect(report).toContain("**Target:** Delete records (MCPTool)");
    expect(report).toContain("### Matched Instruction Evidence");
    expect(report).toContain("### Evidence Graph (1 relationships)");
    expect(report).toContain("Agent -[LOADS_INSTRUCTIONS]-> AGENTS.md");
  });
});

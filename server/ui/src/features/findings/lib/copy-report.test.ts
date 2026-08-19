import { describe, expect, it } from "vitest";
import type { Finding } from "@entities/finding/model";
import { buildMarkdownReport } from "./copy-report";

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
    expect(report).toContain("### Access Proof");
    expect(report).toContain("Action ID: action-report");
    expect(report).toContain("Control: initialize / denied / resource_addressed=false");
    expect(report).toContain("Credential: resource_read / allowed / resource_addressed=true");
    expect(report).toContain("Cleanup: not_applicable");
    expect(report).toContain("not observed agent invocation or downstream impact");
  });
});

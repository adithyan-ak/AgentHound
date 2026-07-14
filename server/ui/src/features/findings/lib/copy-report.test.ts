import { describe, expect, it } from "vitest";
import type { Finding } from "@entities/finding/model";
import { buildMarkdownReport } from "./copy-report";

describe("buildMarkdownReport verification", () => {
  it("includes structured campaign verification metadata", () => {
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
        verification: {
          scenario_id: "cred-reach",
          scenario_version: 1,
          campaign_run_id: "run-report",
          verified_at: "2026-07-13T12:00:00Z",
          oracle_type: "differential_credential_reach",
          outcome: "credential_gated_reach_verified",
          control_stage: "initialize",
          control_status: "denied",
          control_resource_addressed: false,
          authed_stage: "resource_read",
          authed_status: "allowed",
          authed_resource_addressed: true,
          cleanup_status: "not_applicable",
        },
      },
      owasp_map: [],
      atlas_map: [],
    };
    const report = buildMarkdownReport(finding, null, []);
    expect(report).toContain("### Campaign Verification");
    expect(report).toContain("Run: run-report");
    expect(report).toContain("Control: initialize / denied / resource_addressed=false");
    expect(report).toContain("Cleanup: not_applicable");
    expect(report).toContain("not observed agent invocation or impact");
  });
});

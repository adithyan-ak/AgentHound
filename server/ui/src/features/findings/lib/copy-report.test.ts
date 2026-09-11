import { describe, expect, it } from "vitest";
import type { Finding, PublishedFindingScope } from "@entities/finding/model";
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
    const report = buildMarkdownReport(finding, null, [], {
      scope: "published", scan_id: "scan-1", revision: 7,
      published_at: "2026-09-10T12:00:00Z", projection_status: "complete",
      snapshot_status: "complete", available: true, stale: false,
      evidence_state: "persisted_exact_evidence",
    });
    expect(report).toContain("Revision: 7 | Published: 2026-09-10T12:00:00Z");
    expect(report).toContain("Observed: 2026-07-13T12:00:00Z");
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

const snapshot: PublishedFindingScope = {
  mode: "published", scanId: "scan-1", revision: 7,
  publishedAt: "2026-09-10T12:00:00Z", projectionStatus: "complete",
  snapshotStatus: "complete", available: true, stale: false,
};

describe("table export snapshot context", () => {
  it("retains identity and qualifies stale, limited evidence", () => {
    const report = buildFindingsTableMarkdown([], {
      snapshot: { ...snapshot, stale: true, coverageLimited: true },
    });
    expect(report).toContain("scan-1 | Revision: 7 | Published: 2026-09-10T12:00:00Z");
    expect(report).toContain("Stale snapshot");
    expect(report).toContain("missing evidence is not proof of absence");
  });

  it("does not call a failed refresh current or mistake missing scope for an all-clear", () => {
    expect(buildFindingsTableMarkdown([], { snapshot, refreshFailed: true }))
      .toContain("current status is unknown");
    expect(buildFindingsTableMarkdown([])).toContain("Snapshot:** Unavailable");
  });

  it("includes coverage limitations supplied by the matching posture without inventing warnings", () => {
    expect(buildFindingsTableMarkdown([], { snapshot, coverageLimited: true })).toContain("**Coverage:** Limited");
    const report = buildFindingsTableMarkdown([], { snapshot });
    expect(report).not.toContain("**Freshness:**");
    expect(report).not.toContain("**Coverage:**");
  });
});

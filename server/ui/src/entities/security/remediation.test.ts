import { describe, expect, it } from "vitest";
import type { APIEdge, APINode } from "@entities/graph/dto";
import { deriveRemediations } from "./remediation";

function node(kind: string, properties: Record<string, unknown>): APINode {
  return { id: "node-1", kinds: [kind], properties };
}

describe("deriveRemediations evidence states", () => {
  it("does not recommend rotation for a masked identity", () => {
    const items = deriveRemediations(
      node("Credential", {
        merge_key: "identity",
        material_status: "masked",
        exposure_status: "not_observed",
      }),
      "Credential",
      [],
    );
    expect(items.some((item) => item.title === "Rotate this credential")).toBe(false);
    expect(
      items.some((item) => item.title === "Credential material was not observed"),
    ).toBe(true);
  });

  it("surfaces unknown auth and pinning instead of a clean gap", () => {
    const items = deriveRemediations(
      node("MCPServer", {
        auth_method: "unknown",
        pinning_status: "unknown",
      }),
      "MCPServer",
      [],
    );
    expect(items.map((item) => item.title)).toEqual(
      expect.arrayContaining([
        "Verify package pinning",
        "Verify authentication posture",
      ]),
    );
  });

  it("requires explicit anonymous-probe evidence for no-auth advice", () => {
    const unsupported = deriveRemediations(
      node("MCPServer", { auth_method: "none", auth_evidence: "unknown" }),
      "MCPServer",
      [],
    );
    expect(unsupported.some((item) => item.title === "Add an authentication method")).toBe(
      false,
    );
    expect(unsupported.some((item) => item.title === "Verify authentication posture")).toBe(
      true,
    );

    const unprovenRawClaim = deriveRemediations(
      node("MCPServer", {
        auth_method: "none",
        auth_assurance: "unauthenticated",
        auth_evidence: "anonymous_probe_succeeded",
      }),
      "MCPServer",
      [],
    );
    expect(unprovenRawClaim.some((item) => item.title === "Add an authentication method")).toBe(
      false,
    );

    const observedRuntime = deriveRemediations(
      node("MCPServer", {
        auth_method: "unknown",
        auth_evidence: "unknown",
        transport: "http",
        status: "reachable",
        observed_auth_method: "none",
        observed_auth_assurance: "unauthenticated",
        observed_auth_evidence: "anonymous_probe_succeeded",
      }),
      "MCPServer",
      [],
    );
    expect(
      observedRuntime.some((item) => item.title === "Add an authentication method"),
    ).toBe(true);
    expect(
      observedRuntime.some((item) => item.title === "Verify authentication posture"),
    ).toBe(false);
  });

  it("requires explicit exposure evidence and retains the recorded source", () => {
    const incomplete = deriveRemediations(
      node("Credential", { type: "hardcoded" }),
      "Credential",
      [],
    );
    expect(incomplete.some((item) => item.title === "Rotate this credential")).toBe(false);

    const observed = deriveRemediations(
      node("Credential", {
        material_status: "observed",
        exposure_status: "exposed",
        merge_key: "value_hash",
        source: "Authorization header",
      }),
      "Credential",
      [],
    );
    const rotation = observed.find((item) => item.title === "Rotate this credential");
    expect(rotation?.body).toContain("Authorization header");
    expect(rotation?.body).not.toMatch(/config file or environment variable/i);
  });

  it("labels cross-protocol host correlation as a hypothesis", () => {
    const subject = node("A2AAgent", { auth_method: "unknown" });
    const edges: APIEdge[] = [
      {
        source: subject.id,
        target: "resource-1",
        kind: "CAN_REACH",
        properties: { cross_protocol: true, confidence: 0.5 },
      },
    ];

    const items = deriveRemediations(subject, "A2AAgent", edges);
    const correlation = items.find(
      (item) => item.title === "Verify the cross-protocol correlation",
    );
    expect(correlation?.severity).toBe("medium");
    expect(correlation?.body).toMatch(/50%-confidence.*hypothesis/i);
  });
});

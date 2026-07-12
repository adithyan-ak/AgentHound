import { describe, expect, it } from "vitest";
import type { APIEdge } from "@entities/graph/dto";
import { computeClickNeighbors } from "../click-neighbors";

const edges: APIEdge[] = [
  {
    source: "agent",
    target: "peer",
    kind: "CAN_IMPERSONATE",
    properties: {},
  },
  {
    source: "service",
    target: "credential",
    kind: "EXPOSES_CREDENTIAL",
    properties: {},
  },
  {
    source: "peer",
    target: "agent",
    kind: "TRUSTS_SERVER",
    properties: {},
  },
];

describe("computeClickNeighbors", () => {
  it("uses the exact rendered relationship scope", () => {
    const result = computeClickNeighbors("agent", edges, {
      edgeIds: new Set(["agent|peer|CAN_IMPERSONATE"]),
    });

    expect(result.nodeIds).toEqual(expect.arrayContaining(["agent", "peer"]));
    expect(result.edgeIds).toEqual(["agent|peer|CAN_IMPERSONATE"]);
  });

  it("does not include a reverse edge merely because endpoints match", () => {
    const result = computeClickNeighbors("agent", edges, {
      edgeIds: new Set(["agent|peer|CAN_IMPERSONATE"]),
      direction: "out",
    });

    expect(result.edgeIds).not.toContain("peer|agent|TRUSTS_SERVER");
  });

  it("supports credential exposure when that edge is rendered", () => {
    const result = computeClickNeighbors("service", edges, {
      edgeIds: new Set(["service|credential|EXPOSES_CREDENTIAL"]),
    });

    expect(result.nodeIds).toContain("credential");
    expect(result.edgeIds).toContain(
      "service|credential|EXPOSES_CREDENTIAL",
    );
  });
});

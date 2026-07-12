import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { AttackPathDiagram } from "../AttackPathDiagram";
import type { AttackPath } from "@entities/finding/model";

const endpoints = {
  severity: "high",
  sourceId: "s",
  sourceName: "source-agent",
  sourceKind: "AgentInstance",
  targetId: "t",
  targetName: "target-cred",
  targetKind: "Credential",
};

describe("AttackPathDiagram", () => {
  it("does not fabricate an edge label when there is no path", () => {
    render(<AttackPathDiagram path={null} {...endpoints} />);
    expect(screen.getByText("path unresolved")).toBeInTheDocument();
    expect(screen.getByText(/intermediate path not reconstructed/i)).toBeInTheDocument();
    // The endpoints are shown but joined by a "gap" marker, never a "—" edge.
    expect(screen.getByText("gap")).toBeInTheDocument();
    expect(screen.queryByText("\u2014")).not.toBeInTheDocument();
  });

  it("discloses discontinuity when the evidence is not one continuous chain", () => {
    const path: AttackPath = {
      nodes: [
        { id: "s", kinds: ["AgentInstance"], properties: { name: "source-agent" } },
        { id: "m", kinds: ["MCPServer"], properties: { name: "mid" } },
        { id: "x", kinds: ["MCPServer"], properties: { name: "other" } },
        { id: "t", kinds: ["Credential"], properties: { name: "target-cred" } },
      ],
      edges: [
        { source: "s", target: "m", kind: "CAN_REACH", properties: {} },
        { source: "x", target: "t", kind: "HAS_ACCESS_TO", properties: {} },
      ],
      total_risk_weight: null,
    };
    render(<AttackPathDiagram path={path} {...endpoints} />);
    expect(screen.getByText(/does not form one continuous chain/i)).toBeInTheDocument();
    expect(screen.getByText(/disconnected segments/i)).toBeInTheDocument();
  });

  it("renders a continuous chain without a discontinuity warning", () => {
    const path: AttackPath = {
      nodes: [
        { id: "s", kinds: ["AgentInstance"], properties: { name: "source-agent" } },
        { id: "m", kinds: ["MCPServer"], properties: { name: "mid" } },
        { id: "t", kinds: ["Credential"], properties: { name: "target-cred" } },
      ],
      edges: [
        { source: "s", target: "m", kind: "CAN_REACH", properties: {} },
        { source: "m", target: "t", kind: "HAS_ACCESS_TO", properties: {} },
      ],
      total_risk_weight: 1.2,
    };
    render(<AttackPathDiagram path={path} {...endpoints} />);
    expect(screen.getByText("02 hops")).toBeInTheDocument();
    expect(screen.queryByText(/does not form one continuous chain/i)).not.toBeInTheDocument();
  });
});

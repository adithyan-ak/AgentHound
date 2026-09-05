import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LensEdgeData } from "../model/graph";
import { useExplorerStore } from "../model/store";
import { EDGE_COLORS } from "@shared/theme/tokens";
import { EdgeDetailDrawer } from "./EdgeDetailDrawer";

const mocks = vi.hoisted(() => ({
  useExplorerGraph: vi.fn(),
}));

vi.mock("../model/useExplorerGraph", () => ({
  useExplorerGraph: mocks.useExplorerGraph,
}));

const credentialReach: LensEdgeData = {
  kind: "CAN_REACH",
  sourceKind: "AgentInstance",
  targetKind: "Credential",
  severity: "medium",
  confidence: 0.8,
  isComposite: true,
  isCrossProtocol: false,
  bundledCount: 1,
  bundledKinds: ["CAN_REACH"],
  bundledEdges: [
    {
      kind: "CAN_REACH",
      confidence: 0.8,
      severity: "medium",
      properties: {},
    },
  ],
  properties: {},
  dim: false,
  emphasized: false,
  showFlowDot: false,
  color: EDGE_COLORS.attack,
};

describe("EdgeDetailDrawer relationship semantics", () => {
  beforeEach(() => {
    mocks.useExplorerGraph.mockReturnValue({
      data: {
        nodes: [
          {
            id: "agent",
            kinds: ["AgentInstance"],
            properties: { name: "Agent" },
          },
          {
            id: "credential",
            kinds: ["Credential"],
            properties: { name: "Credential" },
          },
        ],
        findings: [],
      },
    });
    useExplorerStore.setState({
      selectedEdge: {
        id: "agent|credential|CAN_REACH",
        source: "agent",
        target: "credential",
        data: credentialReach,
      },
    });
  });

  it("calls a CAN_REACH Credential target a credential", () => {
    render(
      <MemoryRouter>
        <EdgeDetailDrawer />
      </MemoryRouter>,
    );

    expect(screen.getByText("Agent can reach credential")).toBeInTheDocument();
    expect(screen.queryByText("Agent can reach resource")).not.toBeInTheDocument();
  });

  it("shows configured backend evidence and observation time", () => {
    const properties = {
      evidence_state: "configured",
      last_seen: "2026-08-27T12:00:00Z",
      evidence: {
        source: "knowledge_external_connections",
        connection_ids: ["fixture-link"],
      },
    };
    useExplorerStore.setState({
      selectedEdge: {
        id: "agent|credential|USES_BACKEND",
        source: "agent",
        target: "credential",
        data: {
          ...credentialReach,
          kind: "USES_BACKEND",
          bundledKinds: ["USES_BACKEND"],
          bundledEdges: [
            {
              kind: "USES_BACKEND",
              confidence: 1,
              severity: null,
              properties,
            },
          ],
          properties,
        },
      },
    });

    render(
      <MemoryRouter>
        <EdgeDetailDrawer />
      </MemoryRouter>,
    );

    expect(screen.getByText(/knowledge_external_connections/)).toBeInTheDocument();
    expect(screen.getByText("observed at")).toBeInTheDocument();
    expect(screen.getByText("2026-08-27T12:00:00Z")).toBeInTheDocument();
    expect(screen.getByText(/not directly verified/)).toBeInTheDocument();
  });
});

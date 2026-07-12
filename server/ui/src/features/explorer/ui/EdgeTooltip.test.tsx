import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import type { LensEdgeData } from "../model/graph";
import { useExplorerStore } from "../model/store";
import { EDGE_COLORS } from "@shared/theme/tokens";
import { EdgeTooltip } from "./EdgeTooltip";

const configuredReference: LensEdgeData = {
  kind: "EXPOSES",
  sourceKind: "OpenWebUIInstance",
  targetKind: "OllamaInstance",
  severity: null,
  confidence: 1,
  isComposite: false,
  isCrossProtocol: false,
  bundledCount: 1,
  bundledKinds: ["EXPOSES"],
  bundledEdges: [],
  properties: {
    assertion_type: "configured_reference",
    confidence_scope: "configuration_presence",
    confidence: 1,
  },
  dim: false,
  emphasized: false,
  showFlowDot: false,
  color: EDGE_COLORS.structure,
};

describe("EdgeTooltip configured backend evidence", () => {
  beforeEach(() => {
    useExplorerStore.setState({
      selectedEdge: null,
      hoveredEdge: {
        id: "webui|ollama|EXPOSES",
        source: "webui",
        target: "ollama",
        data: configuredReference,
        x: 10,
        y: 10,
      },
    });
  });

  it("scopes certainty to configuration presence, not service existence", () => {
    render(<EdgeTooltip />);

    expect(
      screen.getByText(
        /Configuration references this backend; service existence was not probed/i,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/configuration presence/i)).toBeInTheDocument();
    expect(screen.getByText("100%")).toBeInTheDocument();
    expect(screen.queryByText("Exposes AI service")).not.toBeInTheDocument();
    expect(
      screen.getByText(/backend availability and authentication were not directly verified/i),
    ).toBeInTheDocument();
  });
});

describe("EdgeTooltip relationship semantics", () => {
  beforeEach(() => {
    useExplorerStore.setState({
      selectedEdge: null,
      hoveredEdge: null,
    });
  });

  it("presents observed credential exposure as observed, not reference-only", () => {
    const observedCredential: LensEdgeData = {
      ...configuredReference,
      kind: "EXPOSES_CREDENTIAL",
      targetKind: "Credential",
      bundledKinds: ["EXPOSES_CREDENTIAL"],
      properties: {
        assertion_type: "credential_reference",
        exposure_status: "exposed",
      },
    };
    useExplorerStore.setState({
      hoveredEdge: {
        id: "service|credential|EXPOSES_CREDENTIAL",
        source: "service",
        target: "credential",
        data: observedCredential,
        x: 10,
        y: 10,
      },
    });

    render(<EdgeTooltip />);

    expect(screen.getByText("OBSERVED CREDENTIAL EXPOSURE")).toBeInTheDocument();
    expect(
      screen.getByText("AI service exposes observed credential material"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/reports credential reference/i)).not.toBeInTheDocument();
  });

  it("calls a reachable Credential a credential, not a resource", () => {
    const credentialReach: LensEdgeData = {
      ...configuredReference,
      kind: "CAN_REACH",
      targetKind: "Credential",
      isComposite: true,
      bundledKinds: ["CAN_REACH"],
      properties: { confidence: 0.8 },
    };
    useExplorerStore.setState({
      hoveredEdge: {
        id: "agent|credential|CAN_REACH",
        source: "agent",
        target: "credential",
        data: credentialReach,
        x: 10,
        y: 10,
      },
    });

    render(<EdgeTooltip />);

    expect(screen.getByText("Agent can reach credential")).toBeInTheDocument();
    expect(screen.queryByText("Agent can reach resource")).not.toBeInTheDocument();
  });
});

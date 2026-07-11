import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import type { LensEdgeData } from "../model/graph";
import { useExplorerStore } from "../model/store";
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
  color: "#ffffff",
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

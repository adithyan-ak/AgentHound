import { render, screen, fireEvent } from "@testing-library/react";
import { beforeEach, describe, it, expect } from "vitest";
import { BlastControls } from "../BlastControls";
import { useExplorerStore } from "@features/explorer/model/store";

beforeEach(() => {
  useExplorerStore.setState({
    activeLens: "topology",
    blastRadiusDirection: "out",
    blastRadiusMaxHops: 6,
    blastRadiusSourceId: null,
  });
});

describe("BlastControls", () => {
  it("renders nothing outside the blast-radius lens", () => {
    const { container } = render(<BlastControls />);
    expect(container).toBeEmptyDOMElement();
  });

  it("discloses the bounded, directional traversal on the blast-radius lens", () => {
    useExplorerStore.setState({ activeLens: "blast-radius" });
    render(<BlastControls />);
    // The hop limit and direction are disclosed, not hidden behind a fixed
    // "everything reachable" claim.
    expect(screen.getByText(/6 hops/i)).toBeInTheDocument();
    expect(
      screen.getByRole("group", { name: /blast radius traversal controls/i }),
    ).toBeInTheDocument();
  });

  it("changes direction and hop limit through the store", () => {
    useExplorerStore.setState({
      activeLens: "blast-radius",
      blastRadiusSourceId: "n1",
    });
    render(<BlastControls />);

    fireEvent.click(screen.getByRole("button", { name: /inbound/i }));
    expect(useExplorerStore.getState().blastRadiusDirection).toBe("in");

    fireEvent.click(screen.getByRole("button", { name: /increase hop limit/i }));
    expect(useExplorerStore.getState().blastRadiusMaxHops).toBe(7);
  });

  it("clamps the hop limit at its lower bound", () => {
    useExplorerStore.setState({ activeLens: "blast-radius", blastRadiusMaxHops: 1 });
    render(<BlastControls />);
    const dec = screen.getByRole("button", { name: /decrease hop limit/i });
    expect(dec).toBeDisabled();
  });
});

import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { useExplorerStore } from "../model/store";
import { LensBar } from "./LensBar";

describe("LensBar responsive access", () => {
  beforeEach(() => {
    useExplorerStore.setState({ activeLens: "attack-surface" });
  });

  it("caps the strip to the viewport and preserves horizontal access", () => {
    render(<LensBar />);

    expect(screen.getByTestId("lens-bar")).toHaveClass(
      "max-w-[calc(100vw-2rem)]",
    );
    expect(screen.getByTestId("lens-bar-scroll")).toHaveClass(
      "overflow-x-auto",
    );
  });

  it("can return to Topology after another lens is active", () => {
    render(<LensBar />);

    fireEvent.click(screen.getByRole("button", { name: "Topology" }));

    expect(useExplorerStore.getState().activeLens).toBe("topology");
  });
});

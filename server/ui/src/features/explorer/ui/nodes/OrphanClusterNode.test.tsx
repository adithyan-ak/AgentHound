import type { ComponentProps } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useExplorerStore } from "@features/explorer/model/store";
import { OrphanClusterNode } from "./OrphanClusterNode";

vi.mock("./NodeHandles", () => ({
  NodeHandles: () => null,
}));

const props = {
  id: "orphan-cluster-MCPTool",
  data: {
    kind: "MCPTool",
    kindTag: "MCP TOOL",
    lensLabel: "Topology",
    count: 2,
    orphanNodes: [
      { id: "tool-1", name: "tool one", kind: "MCPTool" },
      { id: "tool-2", name: "tool two", kind: "MCPTool" },
    ],
  },
  selected: false,
} as unknown as ComponentProps<typeof OrphanClusterNode>;

describe("OrphanClusterNode", () => {
  beforeEach(() => {
    useExplorerStore.setState({
      selectedNodeId: null,
      drawerOpen: false,
    });
  });

  it("exposes the cluster as a semantic keyboard control", () => {
    render(<OrphanClusterNode {...props} />);

    const control = screen.getByRole("button", {
      name: /2 mcp tool nodes outside the topology lens relationship scope/i,
    });
    expect(control).toHaveAttribute("aria-expanded", "false");

    fireEvent.focus(control);
    expect(control).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/outside topology lens scope/i)).toBeInTheDocument();

    fireEvent.keyDown(control, { key: "Escape" });
    expect(control).toHaveAttribute("aria-expanded", "false");
  });
});

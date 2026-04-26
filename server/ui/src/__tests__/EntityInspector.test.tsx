import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EntityInspector } from "@/components/inspector/EntityInspector";
import { useGraphStore } from "@/store/graph";

vi.mock("@/api/graph", () => ({
  fetchNode: vi.fn(),
  fetchGraphStats: vi.fn(),
  fetchNodes: vi.fn(),
  fetchEdges: vi.fn(),
}));

import { fetchNode } from "@/api/graph";

const mockedFetchNode = vi.mocked(fetchNode);

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
  };
}

describe("EntityInspector", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useGraphStore.setState({ selectedNodeId: null });
  });

  it("shows empty state when no node is selected", () => {
    render(<EntityInspector />, { wrapper: createWrapper() });
    expect(screen.getByText("Click a node or edge to inspect it")).toBeInTheDocument();
  });

  it("renders node details when a node is selected", async () => {
    useGraphStore.setState({ selectedNodeId: "test-node-1" });

    mockedFetchNode.mockResolvedValue({
      node: {
        id: "test-node-1",
        kinds: ["MCPServer"],
        properties: {
          name: "My Server",
          risk_score: 75,
          auth_method: "none",
        },
      },
      edges: [],
    });

    render(<EntityInspector />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "My Server" })).toBeInTheDocument();
    });

    expect(screen.getByText("MCPServer")).toBeInTheDocument();
    expect(screen.getAllByText("75").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Props")).toBeInTheDocument();
    expect(screen.getByText("Links")).toBeInTheDocument();
    expect(screen.getByText("Risk")).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();
  });

  it("shows not found when node data returns null", async () => {
    useGraphStore.setState({ selectedNodeId: "nonexistent" });

    mockedFetchNode.mockResolvedValue(
      null as unknown as Awaited<ReturnType<typeof fetchNode>>,
    );

    render(<EntityInspector />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Node not found")).toBeInTheDocument();
    });
  });

  it("shows loading skeleton when fetching", () => {
    useGraphStore.setState({ selectedNodeId: "loading-node" });

    mockedFetchNode.mockReturnValue(new Promise(() => {}));

    const { container } = render(<EntityInspector />, {
      wrapper: createWrapper(),
    });

    const skeletons = container.querySelectorAll('[class*="animate-pulse"]');
    expect(skeletons.length).toBeGreaterThanOrEqual(1);
  });
});

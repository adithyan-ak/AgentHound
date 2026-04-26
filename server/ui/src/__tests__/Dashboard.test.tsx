import { render, screen } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StatCards } from "@/components/dashboard/StatCards";

vi.mock("@/hooks/useGraph", () => ({
  useGraphStats: vi.fn(),
}));

vi.mock("@/api/analysis", () => ({
  fetchFindings: vi.fn().mockResolvedValue([]),
}));

vi.mock("@/api/graph", () => ({
  fetchNodes: vi.fn().mockResolvedValue([]),
}));

vi.mock("@/api/scans", () => ({
  fetchScans: vi.fn().mockResolvedValue([]),
}));

import { useGraphStats } from "@/hooks/useGraph";

const mockedUseGraphStats = vi.mocked(useGraphStats);

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

describe("StatCards", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders loading skeletons when data is loading", () => {
    mockedUseGraphStats.mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      isError: false,
      isPending: true,
    } as unknown as ReturnType<typeof useGraphStats>);

    const { container } = render(<StatCards />, { wrapper: createWrapper() });
    const skeletons = container.querySelectorAll('[class*="animate-pulse"]');
    expect(skeletons.length).toBeGreaterThanOrEqual(5);
  });

  it("renders stat cards with correct values", () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: {
          AgentInstance: 3,
          MCPServer: 5,
          A2AAgent: 2,
          MCPTool: 12,
        },
        edge_counts: {},
        total_nodes: 42,
        total_edges: 100,
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<StatCards />, { wrapper: createWrapper() });

    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();

    expect(screen.getByText("Exposure")).toBeInTheDocument();
    expect(screen.getByText("Agents")).toBeInTheDocument();
    expect(screen.getByText("MCP Servers")).toBeInTheDocument();
    expect(screen.getByText("A2A Agents")).toBeInTheDocument();
    expect(screen.getByText("Tools")).toBeInTheDocument();
  });

  it("renders zero values when node_counts keys are missing", () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: {},
        edge_counts: {},
        total_nodes: 0,
        total_edges: 0,
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<StatCards />, { wrapper: createWrapper() });

    const zeros = screen.getAllByText("0");
    expect(zeros).toHaveLength(5);
  });
});

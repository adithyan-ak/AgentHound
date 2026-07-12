import { render, screen } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Dashboard } from "@features/dashboard";
import { StatCards } from "@features/dashboard/ui/StatCards";

vi.mock("@entities/graph-stats/api", () => ({
  useGraphStats: vi.fn(),
  useFreshness: vi.fn(() => ({ data: undefined })),
  fetchDashboardExport: vi.fn().mockResolvedValue({}),
}));

vi.mock("@entities/finding/api", () => ({
  fetchFindings: vi.fn().mockResolvedValue([]),
}));

vi.mock("@entities/node/api", () => ({
  fetchNodes: vi.fn().mockResolvedValue([]),
}));

vi.mock("@entities/scan/api", () => ({
  fetchScans: vi.fn().mockResolvedValue([]),
}));

import { useGraphStats } from "@entities/graph-stats/api";

const mockedUseGraphStats = vi.mocked(useGraphStats);

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      </MemoryRouter>
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

    expect(screen.getByText("Agents")).toBeInTheDocument();
    expect(screen.getByText("MCP Servers")).toBeInTheDocument();
    expect(screen.getByText("A2A Agents")).toBeInTheDocument();
    expect(screen.getByText("Tools")).toBeInTheDocument();
    expect(screen.getByText("Credentials")).toBeInTheDocument();
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

    // One "0" per KPI tile (Agents, MCP Servers, A2A Agents, Tools, Credentials).
    const zeros = screen.getAllByText("0");
    expect(zeros).toHaveLength(5);
  });
});

describe("Dashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders an error state when graph stats fail", () => {
    mockedUseGraphStats.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("stats unavailable"),
      isError: true,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(screen.getByRole("alert")).toHaveTextContent("Dashboard unavailable");
    expect(screen.queryByText("No attack surface mapped")).not.toBeInTheDocument();
  });

  it("shows the all-clear empty state only for an authoritative, empty graph", () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: {},
        edge_counts: {},
        total_nodes: 0,
        total_edges: 0,
        completeness: {
          complete: true,
          coverage_status: "complete",
          generation_ids: ["g1"],
          truncated: false,
        },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });
    expect(screen.getByText("No attack surface mapped")).toBeInTheDocument();
  });

  it("does NOT show all-clear for a partial/incomplete empty read", () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: {},
        edge_counts: {},
        total_nodes: 0,
        total_edges: 0,
        completeness: {
          complete: false,
          coverage_status: "partial",
          generation_ids: ["g1"],
          truncated: false,
          source_errors: ["mcp: connection refused"],
        },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });
    // A partial read with zero nodes must not masquerade as "all clear".
    expect(screen.queryByText("No attack surface mapped")).not.toBeInTheDocument();
    // Instead it discloses the incompleteness.
    expect(screen.getByText(/not authoritative/i)).toBeInTheDocument();
  });
});

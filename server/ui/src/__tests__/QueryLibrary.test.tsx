import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { QueryLibrary } from "@/components/queries/QueryLibrary";
import type { PreBuiltQuery } from "@/api/types";

vi.mock("@/api/analysis", () => ({
  fetchPreBuiltQueries: vi.fn(),
  runPreBuiltQuery: vi.fn(),
  fetchFindings: vi.fn(),
  findShortestPath: vi.fn(),
  findAllPaths: vi.fn(),
  findWeightedPath: vi.fn(),
}));

import { fetchPreBuiltQueries, runPreBuiltQuery } from "@/api/analysis";

const mockedFetchQueries = vi.mocked(fetchPreBuiltQueries);
const mockedRunQuery = vi.mocked(runPreBuiltQuery);

const mockQueries: PreBuiltQuery[] = [
  { id: "agents-shell-access", name: "Agents with Shell Access", description: "Find agents that can execute shell commands", category: "Critical Paths", severity: "critical", owasp_map: ["MCP01"] },
  { id: "poisoned-tools", name: "Poisoned Tools", description: "Tools with injection patterns", category: "Vulnerabilities", severity: "high", owasp_map: ["MCP04"] },
  { id: "unpinned-packages", name: "Unpinned Packages", description: "Unpinned npm packages", category: "Supply Chain", severity: "medium" },
  { id: "chokepoint-servers", name: "Chokepoint Servers", description: "High betweenness centrality", category: "Chokepoints", severity: "medium" },
  { id: "unpinned-shell", name: "Unpinned Shell", description: "Unpinned with shell access", category: "Combined", severity: "critical", owasp_map: ["MCP01", "MCP09"] },
];

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

describe("QueryLibrary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders loading skeletons while queries are loading", () => {
    mockedFetchQueries.mockReturnValue(new Promise(() => {}));

    const { container } = render(<QueryLibrary />, {
      wrapper: createWrapper(),
    });
    const skeletons = container.querySelectorAll('[class*="animate-pulse"]');
    expect(skeletons.length).toBeGreaterThanOrEqual(1);
  });

  it("renders query cards grouped by category", async () => {
    mockedFetchQueries.mockResolvedValue(mockQueries);

    render(<QueryLibrary />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Agents with Shell Access")).toBeInTheDocument();
    });

    expect(screen.getByText("Critical Paths")).toBeInTheDocument();
    expect(screen.getByText("Vulnerabilities")).toBeInTheDocument();
    expect(screen.getByText("Supply Chain")).toBeInTheDocument();
    expect(screen.getByText("Chokepoints")).toBeInTheDocument();
    expect(screen.getByText("Combined")).toBeInTheDocument();

    expect(screen.getByText("Poisoned Tools")).toBeInTheDocument();
    expect(screen.getByText("Unpinned Packages")).toBeInTheDocument();
    expect(screen.getByText("Chokepoint Servers")).toBeInTheDocument();
    expect(screen.getByText("Unpinned Shell")).toBeInTheDocument();
  });

  it("renders severity badges", async () => {
    mockedFetchQueries.mockResolvedValue(mockQueries);

    render(<QueryLibrary />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Agents with Shell Access")).toBeInTheDocument();
    });

    const criticalBadges = screen.getAllByText("critical");
    expect(criticalBadges.length).toBe(2);
    expect(screen.getAllByText("medium").length).toBe(2);
    expect(screen.getByText("high")).toBeInTheDocument();
  });

  it("renders OWASP tags when present", async () => {
    mockedFetchQueries.mockResolvedValue(mockQueries);

    render(<QueryLibrary />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Agents with Shell Access")).toBeInTheDocument();
    });

    expect(screen.getAllByText("MCP01").length).toBe(2);
    expect(screen.getByText("MCP04")).toBeInTheDocument();
    expect(screen.getByText("MCP09")).toBeInTheDocument();
  });

  it("expands query card and shows results on click", async () => {
    mockedFetchQueries.mockResolvedValue(mockQueries);
    mockedRunQuery.mockResolvedValue({
      query: mockQueries[0]!,
      rows: [{ name: "test-server", risk: 85 }],
    });

    render(<QueryLibrary />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Agents with Shell Access")).toBeInTheDocument();
    });

    const queryButton = screen.getByText("Agents with Shell Access").closest("button");
    fireEvent.click(queryButton!);

    await waitFor(() => {
      expect(screen.getByText("test-server")).toBeInTheDocument();
    });

    expect(screen.getByText("85")).toBeInTheDocument();
  });
});

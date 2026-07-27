import { render, screen, within } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Dashboard } from "@features/dashboard";
import { StatCards } from "@features/dashboard/ui/StatCards";
import { ExposureGauge } from "@features/dashboard/ui/ExposureGauge";
import type { Finding } from "@entities/finding/model";
import { useProjectionState } from "@entities/posture";

const publishedScan = vi.hoisted(() => ({
  id: "scan-1",
  collector: "mcp",
  status: "completed",
  started_at: "2026-07-11T00:00:00Z",
  completed_at: "2026-07-11T00:01:00Z",
  submitted: { nodes: 0, edges: 0 },
  write_rows: { nodes: 0, edges: 0 },
  graph_totals: { before: null, after: { total_nodes: 0, total_edges: 0 } },
  collection_status: "complete",
  graph_status: "complete",
  analysis_status: "complete",
  snapshot_status: "complete",
  projection_status: "complete",
  publication_status: "published",
  published_revision: 1,
  published_at: "2026-07-11T00:01:00Z",
}));

vi.mock("@entities/graph-stats/api", () => ({
  useGraphStats: vi.fn(),
}));

vi.mock("@entities/finding/api", () => ({
  fetchFindings: vi.fn().mockResolvedValue({
    findings: [],
    scope: {
      mode: "published",
      scanId: "scan-1",
      revision: 1,
      publishedAt: "2026-07-11T00:00:00Z",
      projectionStatus: "complete",
      snapshotStatus: "complete",
      available: true,
      stale: false,
    },
  }),
}));

vi.mock("@entities/node/api", () => ({
  fetchNodeCollection: vi.fn().mockResolvedValue({
    items: [],
    total: 0,
    complete: true,
    revision: "graph-revision",
    projection: { scanId: "scan-1", revision: 1 },
  }),
}));

vi.mock("@entities/scan/api", () => ({
  fetchScans: vi.fn().mockResolvedValue([publishedScan]),
  fetchLatestCompletedScan: vi.fn().mockResolvedValue(publishedScan),
  fetchLatestPublishedScan: vi.fn().mockResolvedValue(publishedScan),
}));

vi.mock("@entities/posture/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@entities/posture/api")>();
  return {
    ...actual,
    fetchProjectionState: vi.fn().mockResolvedValue({
      status: "complete",
      scan_id: "scan-1",
      dirty_coverage: [],
      active_coverage_roots: [],
      active_coverage_limitations: [],
      updated_at: "2026-07-11T00:00:00Z",
      published_scan_id: "scan-1",
      published_revision: 1,
      published_at: "2026-07-11T00:01:00Z",
    }),
    useProjectionState: vi.fn(() => ({
      data: {
        status: "complete",
        scan_id: "scan-1",
        dirty_coverage: [],
        active_coverage_roots: [],
        active_coverage_limitations: [],
        updated_at: "2026-07-11T00:00:00Z",
        published_scan_id: "scan-1",
        published_revision: 1,
        published_at: "2026-07-11T00:01:00Z",
      },
      isLoading: false,
      isError: false,
      error: null,
      dataUpdatedAt: Date.parse("2026-07-11T00:00:00Z"),
    })),
  };
});

import { useGraphStats } from "@entities/graph-stats/api";
import { fetchFindings } from "@entities/finding/api";
import { fetchNodeCollection } from "@entities/node/api";

const mockedUseGraphStats = vi.mocked(useGraphStats);
const mockedFetchFindings = vi.mocked(fetchFindings);
const mockedFetchNodeCollection = vi.mocked(fetchNodeCollection);
const mockedUseProjectionState = vi.mocked(useProjectionState);

function completeProjectionState() {
  return {
    data: {
      status: "complete" as const,
      scan_id: "scan-1",
      dirty_coverage: [],
      active_coverage_roots: [],
      active_coverage_limitations: [],
      updated_at: "2026-07-11T00:00:00Z",
      published_scan_id: "scan-1",
      published_revision: 1,
      published_at: "2026-07-11T00:01:00Z",
    },
    isLoading: false,
    isError: false,
    error: null,
    dataUpdatedAt: Date.parse("2026-07-11T00:00:00Z"),
  } as unknown as ReturnType<typeof useProjectionState>;
}

function observedAnonymousNode(id: string) {
  return {
    id,
    kinds: ["MCPServer"],
    properties: {
      auth_method: "unknown",
      auth_assurance: "unknown",
      auth_evidence: "unknown",
      observed_auth_method: "none",
      observed_auth_assurance: "unauthenticated",
      observed_auth_evidence: "anonymous_probe_succeeded",
      effective_auth_method: "none",
      effective_auth_assurance: "unauthenticated",
      effective_auth_evidence: "anonymous_probe_succeeded",
      effective_auth_source: "observed",
    },
  };
}

function nodeCollection(items: ReturnType<typeof observedAnonymousNode>[]) {
  return {
    items,
    total: items.length,
    complete: true,
    revision: "graph-revision",
    projection: {
      scanId: "scan-1",
      revision: 1,
      coverageLimited: false,
      coverageLimitationCount: 0,
    },
  };
}

function highFinding(index: number): Finding {
  return {
    id: `finding-${index}`,
    severity: "high",
    category: "shadowing",
    title: "shadowing",
    description: "shadowing",
    edge_kind: "SHADOWS",
    source_id: `source-${index}`,
    source_name: "source",
    source_kind: "MCPTool",
    target_id: `target-${index}`,
    target_name: "target",
    target_kind: "MCPTool",
    confidence: 1,
    variant: "default",
    evidence: { state: "inferred" },
    owasp_map: [],
    atlas_map: [],
  };
}

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
    publishedScan.collection_status = "complete";
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
        projection: { scanId: "scan-1", revision: 1 },
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
        projection: { scanId: "scan-1", revision: 1 },
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

  it("counts observed anonymous MCP servers in the server tile", async () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-1", revision: 1 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);
    mockedFetchNodeCollection.mockReset();
    mockedFetchNodeCollection.mockResolvedValue(
      nodeCollection([observedAnonymousNode("anonymous")]),
    );

    render(<StatCards />, { wrapper: createWrapper() });

    const tile = (await screen.findByText("1 unauth")).closest(
      ".card-elevated",
    );
    expect(tile).not.toBeNull();
    expect(within(tile as HTMLElement).getByText("1 unauth")).toBeInTheDocument();
  });
});

describe("ExposureGauge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("includes observed anonymous servers in the public exposure index", async () => {
    mockedFetchFindings.mockReset();
    mockedFetchFindings.mockResolvedValue({
      findings: Array.from({ length: 6 }, (_, index) => highFinding(index)),
      scope: {
        mode: "published",
        scanId: "scan-1",
        revision: 1,
        publishedAt: "2026-07-11T00:00:00Z",
        projectionStatus: "complete",
        snapshotStatus: "complete",
        available: true,
        stale: false,
      },
    });
    mockedFetchNodeCollection.mockReset();
    mockedFetchNodeCollection.mockResolvedValue(
      nodeCollection([
        observedAnonymousNode("anonymous-1"),
        observedAnonymousNode("anonymous-2"),
      ]),
    );

    render(<ExposureGauge />, { wrapper: createWrapper() });

    const unauthLabel = await screen.findByText("Unauth Srv");
    expect(screen.getByText("Guarded")).toBeInTheDocument();
    const unauth = unauthLabel.closest("div");
    expect(unauth).not.toBeNull();
    expect(within(unauth as HTMLElement).getByText("02")).toBeInTheDocument();
  });
});

describe("Dashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    publishedScan.collection_status = "complete";
    mockedUseProjectionState.mockReturnValue(completeProjectionState());
    mockedFetchNodeCollection.mockReset();
    mockedFetchNodeCollection.mockResolvedValue(nodeCollection([]));
    mockedFetchFindings.mockReset();
    mockedFetchFindings.mockResolvedValue({
      findings: [],
      scope: {
        mode: "published",
        scanId: "scan-1",
        revision: 1,
        publishedAt: "2026-07-11T00:00:00Z",
        projectionStatus: "complete",
        snapshotStatus: "complete",
        available: true,
        stale: false,
      },
    });
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

  it("withholds all-clear dashboard content when findings fail", async () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-1", revision: 1 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);
    mockedFetchFindings.mockRejectedValueOnce(new Error("findings unavailable"));

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Dashboard unavailable",
    );
    expect(screen.queryByText("No critical alerts")).not.toBeInTheDocument();
    expect(screen.queryByText("Low Risk")).not.toBeInTheDocument();
  });

  it("withholds verdicts when graph and published findings revisions differ", async () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-2", revision: 2 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(await screen.findByText("Posture verdicts withheld")).toBeInTheDocument();
    expect(screen.getByText(/do not identify the same published scan/)).toBeInTheDocument();
    expect(screen.queryByText("Low Risk")).not.toBeInTheDocument();
  });

  it("renders verdict widgets when all sources share one publication", async () => {
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-1", revision: 1 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(await screen.findByText("Low Risk")).toBeInTheDocument();
    expect(
      within(screen.getByText("Threat").closest("div") as HTMLElement).getByText(
        "Low",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText("Posture verdicts withheld")).not.toBeInTheDocument();
  });

  it("qualifies low threat and exposure labels when published roots are limited", async () => {
    mockedUseProjectionState.mockReturnValue({
      ...completeProjectionState(),
      data: {
        ...completeProjectionState().data,
        active_coverage_roots: [
          {
            coverage_key: "config:instruction-exact-user:sha256:root",
            mode: "exact_user",
            state: "partial",
            scan_id: "scan-1",
            observed_at: "2026-07-11T00:00:00Z",
            registry_contract: {
              generation: 1,
              digest: "sha256:registry",
            },
            contract_current: true,
          },
        ],
      },
    } as ReturnType<typeof useProjectionState>);
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-1", revision: 1 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(
      await within(
        screen.getByText("Threat").closest("div") as HTMLElement,
      ).findByText("Low · Limited"),
    ).toBeInTheDocument();
    expect(screen.getByText("Low Risk · Limited Coverage")).toBeInTheDocument();
    expect(screen.getByText("observed score of 100")).toBeInTheDocument();
    expect(
      within(
        screen.getByText("Threat").closest("div") as HTMLElement,
      ).queryByText(/^Low$/),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/^Low Risk$/)).not.toBeInTheDocument();
  });

  it("qualifies posture values for a persisted non-instruction limitation", async () => {
    mockedUseProjectionState.mockReturnValue({
      ...completeProjectionState(),
      data: {
        ...completeProjectionState().data,
        active_coverage_limitations: [
          {
            coverage_key: "mcp:target:sha256:limited",
            state: "failed",
            scan_id: "scan-1",
            observed_at: "2026-07-11T00:00:00Z",
          },
        ],
      },
    } as ReturnType<typeof useProjectionState>);
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-1", revision: 1 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(
      await screen.findByText("Low Risk · Limited Coverage"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Published posture has coverage limitations"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/missing evidence is not proof of absence/i),
    ).toBeInTheDocument();
  });

  it("renders a usable published posture with a deep-coverage warning", async () => {
    publishedScan.collection_status = "truncated";
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-1", revision: 1 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(await screen.findByText("Low Risk")).toBeInTheDocument();
    expect(
      screen.getByText("Published posture has coverage limitations"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Posture verdicts withheld")).not.toBeInTheDocument();
  });

  it("keeps warning after a later exact scan when retained deep coverage is truncated", async () => {
    mockedUseProjectionState.mockReturnValue({
      ...completeProjectionState(),
      data: {
        ...completeProjectionState().data,
        active_coverage_roots: [
          {
            coverage_key: "config:instruction-deep:sha256:root",
            mode: "deep",
            state: "truncated",
            scan_id: "scan-deep",
            observed_at: "2026-07-10T00:00:00Z",
            registry_contract: {
              generation: 1,
              digest: "sha256:registry",
            },
            contract_current: true,
          },
        ],
      },
    } as ReturnType<typeof useProjectionState>);
    mockedUseGraphStats.mockReturnValue({
      data: {
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scanId: "scan-1", revision: 1 },
      },
      isLoading: false,
      error: null,
      isError: false,
      isPending: false,
    } as unknown as ReturnType<typeof useGraphStats>);

    render(<Dashboard />, { wrapper: createWrapper() });

    expect(
      await screen.findByText("Low Risk · Limited Coverage"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/retained nested coverage is truncated/),
    ).toBeInTheDocument();
  });
});

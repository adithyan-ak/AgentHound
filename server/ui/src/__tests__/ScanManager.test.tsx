import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ScanManager } from "@features/scans";
import type { Scan } from "@entities/scan";

vi.mock("@entities/scan/api", () => ({
  fetchScans: vi.fn(),
  deleteScan: vi.fn(),
  uploadScan: vi.fn(),
}));

import { fetchScans } from "@entities/scan/api";

const mockedFetchScans = vi.mocked(fetchScans);

const mockScans: Scan[] = [
  {
    id: "scan-abc12345-def",
    collector: "mcp",
    status: "completed",
    started_at: "2026-04-07T10:00:00Z",
    completed_at: "2026-04-07T10:05:00Z",
    node_count: 42,
    edge_count: 87,
  },
  {
    id: "scan-xyz78901-ghi",
    collector: "config",
    status: "running",
    started_at: "2026-04-08T09:00:00Z",
    node_count: 0,
    edge_count: 0,
  },
  {
    id: "scan-lmn45678-opq",
    collector: "a2a",
    status: "failed",
    started_at: "2026-04-06T14:00:00Z",
    completed_at: "2026-04-06T14:01:00Z",
    node_count: 0,
    edge_count: 0,
    error: "connection refused",
  },
];

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>{children}</MemoryRouter>
      </QueryClientProvider>
    );
  };
}

describe("ScanManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders scan history table with scans", async () => {
    mockedFetchScans.mockResolvedValue(mockScans);

    render(<ScanManager />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("scan-abc")).toBeInTheDocument();
    });

    expect(screen.getByText("scan-xyz")).toBeInTheDocument();
    expect(screen.getByText("scan-lmn")).toBeInTheDocument();

    expect(screen.getByText("mcp")).toBeInTheDocument();
    expect(screen.getByText("config")).toBeInTheDocument();
    expect(screen.getByText("a2a")).toBeInTheDocument();

    expect(screen.getByText("completed")).toBeInTheDocument();
    expect(screen.getByText("running")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();

    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("87")).toBeInTheDocument();
  });

  it("renders completed_with_errors with a friendly label, real counts, and the error", async () => {
    mockedFetchScans.mockResolvedValue([
      {
        id: "scan-err00000-zzz",
        collector: "mcp",
        status: "completed_with_errors",
        started_at: "2026-04-09T10:00:00Z",
        completed_at: "2026-04-09T10:05:00Z",
        node_count: 12,
        edge_count: 7,
        error: "post-processing: cypher syntax error",
      },
    ]);

    render(<ScanManager />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Completed with errors")).toBeInTheDocument();
    });
    // Collection succeeded, so the real non-zero counts still render.
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    // The post-processing error is surfaced (as a tooltip on the status).
    expect(
      screen.getByTitle("post-processing: cypher syntax error"),
    ).toBeInTheDocument();
  });

  it("renders loading state", () => {
    mockedFetchScans.mockReturnValue(new Promise(() => {}));

    const { container } = render(<ScanManager />, {
      wrapper: createWrapper(),
    });

    const skeletons = container.querySelectorAll('[class*="animate-pulse"]');
    expect(skeletons.length).toBeGreaterThanOrEqual(1);
  });

  it("renders empty state when no scans", async () => {
    mockedFetchScans.mockResolvedValue([]);

    render(<ScanManager />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/no scans/i)).toBeInTheDocument();
    });
  });

  it("shows new scan dialog when button is clicked", async () => {
    mockedFetchScans.mockResolvedValue(mockScans);

    render(<ScanManager />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("scan-abc")).toBeInTheDocument();
    });

    const newScanButton = screen.getByRole("button", { name: /new scan/i });
    fireEvent.click(newScanButton);

    await waitFor(() => {
      expect(
        screen.getByText(/agenthound scan --config/i),
      ).toBeInTheDocument();
    });
  });
});

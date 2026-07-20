import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ScanManager } from "@features/scans";
import type { Scan } from "@entities/scan";

vi.mock("@entities/scan/api", () => ({
  fetchScans: vi.fn(),
  fetchScanPage: vi.fn(),
  deleteScan: vi.fn(),
  uploadScan: vi.fn(),
}));

import { deleteScan, fetchScanPage } from "@entities/scan/api";

const mockedFetchScanPage = vi.mocked(fetchScanPage);
const mockedDeleteScan = vi.mocked(deleteScan);

function scanPage(
  scans: Scan[],
  total = scans.length,
  offset = 0,
  revision = "scan-revision",
) {
  const hasMore = offset + scans.length < total;
  return {
    scans,
    total,
    hasMore,
    complete: !hasMore,
    revision,
    revisionConflict: false,
  };
}

const mockScans: Scan[] = [
  {
    id: "scan-abc12345-def",
    collector: "mcp",
    status: "completed",
    started_at: "2026-04-07T10:00:00Z",
    completed_at: "2026-04-07T10:05:00Z",
    submitted: { nodes: 42, edges: 87 },
    write_rows: { nodes: 42, edges: 87 },
    graph_totals: { before: null, after: null },
    metadata: { ruleset: { digest: "sha256:test" } },
  },
  {
    id: "scan-xyz78901-ghi",
    collector: "config",
    status: "running",
    started_at: "2026-04-08T09:00:00Z",
    submitted: { nodes: 0, edges: 0 },
    write_rows: { nodes: 0, edges: 0 },
    graph_totals: { before: null, after: null },
  },
  {
    id: "scan-lmn45678-opq",
    collector: "a2a",
    status: "failed",
    started_at: "2026-04-06T14:00:00Z",
    completed_at: "2026-04-06T14:01:00Z",
    submitted: { nodes: 0, edges: 0 },
    write_rows: { nodes: 0, edges: 0 },
    graph_totals: { before: null, after: null },
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
    mockedDeleteScan.mockReset();
  });

  it("renders scan history table with scans", async () => {
    mockedFetchScanPage.mockResolvedValue(scanPage(mockScans));

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
    expect(
      screen.getByRole("link", {
        name: /view ruleset provenance for scan scan-abc12345-def/i,
      }),
    ).toHaveAttribute("href", "/rules?scan=scan-abc12345-def");
  });

  it("renders completed_with_errors with a friendly label, write rows, and the error", async () => {
    mockedFetchScanPage.mockResolvedValue(scanPage([
      {
        id: "scan-err00000-zzz",
        collector: "mcp",
        status: "completed_with_errors",
        started_at: "2026-04-09T10:00:00Z",
        completed_at: "2026-04-09T10:05:00Z",
        submitted: { nodes: 12, edges: 7 },
        write_rows: { nodes: 12, edges: 7 },
        graph_totals: { before: null, after: null },
        error: "post-processing: cypher syntax error",
      },
    ]));

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
    mockedFetchScanPage.mockReturnValue(new Promise(() => {}));

    const { container } = render(<ScanManager />, {
      wrapper: createWrapper(),
    });

    const skeletons = container.querySelectorAll('[class*="animate-pulse"]');
    expect(skeletons.length).toBeGreaterThanOrEqual(1);
  });

  it("renders empty state when no scans", async () => {
    mockedFetchScanPage.mockResolvedValue(scanPage([]));

    render(<ScanManager />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/no scans/i)).toBeInTheDocument();
    });
  });

  it("withholds the empty state when scan history fails", async () => {
    mockedFetchScanPage.mockRejectedValue(new Error("postgres unavailable"));

    render(<ScanManager />, { wrapper: createWrapper() });

    expect(
      await screen.findByText(/scan history unavailable/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/no scans recorded/i)).not.toBeInTheDocument();
  });

  it("labels a capped page as a subset of the total", async () => {
    mockedFetchScanPage.mockResolvedValue(scanPage(mockScans, 51));

    render(<ScanManager />, { wrapper: createWrapper() });

    expect(
      await screen.findByText(/showing scans 1–3 of 51/i),
    ).toBeInTheDocument();
    expect(screen.getByText("51")).toBeInTheDocument();
  });

  it("passes the first-page revision when requesting the next page", async () => {
    mockedFetchScanPage
      .mockResolvedValueOnce(scanPage(mockScans, 51))
      .mockResolvedValueOnce(
        scanPage(
          [
            {
              ...mockScans[0]!,
              id: "scan-oldest-page",
            },
          ],
          51,
          50,
        ),
      );

    render(<ScanManager />, { wrapper: createWrapper() });

    fireEvent.click(await screen.findByRole("button", { name: "Next" }));

    await waitFor(() => {
      expect(mockedFetchScanPage).toHaveBeenLastCalledWith(
        50,
        50,
        "scan-revision",
      );
    });
    expect(await screen.findByText("scan-old")).toBeInTheDocument();
  });

  it("restarts a conflicted pagination session with the current revision", async () => {
    mockedFetchScanPage
      .mockResolvedValueOnce(scanPage(mockScans, 51, 0, "scan-revision-1"))
      .mockResolvedValueOnce({
        scans: [],
        total: 0,
        hasMore: false,
        complete: false,
        revision: "scan-revision-2",
        revisionConflict: true,
      })
      .mockResolvedValueOnce(scanPage(mockScans, 51, 0, "scan-revision-2"));

    render(<ScanManager />, { wrapper: createWrapper() });

    fireEvent.click(await screen.findByRole("button", { name: "Next" }));
    fireEvent.click(
      await screen.findByRole("button", { name: /restart pagination/i }),
    );

    await waitFor(() => {
      expect(mockedFetchScanPage).toHaveBeenLastCalledWith(
        50,
        0,
        "scan-revision-2",
      );
    });
  });

  it("keeps the delete dialog usable after a 409 active-coverage-head rejection", async () => {
    mockedFetchScanPage.mockResolvedValue(scanPage(mockScans));
    mockedDeleteScan.mockRejectedValueOnce(
      Object.assign(new Error("scan owns an active coverage head"), {
        status: 409,
        code: "SCAN_DELETE_CONFLICT",
      }),
    );

    render(<ScanManager />, { wrapper: createWrapper() });

    const deleteButtons = await screen.findAllByTitle("Delete scan history");
    expect(deleteButtons[0]).toBeEnabled();
    fireEvent.click(deleteButtons[0]!);
    fireEvent.click(
      await screen.findByRole("button", { name: "Delete scan" }),
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Scan was not deleted: scan owns an active coverage head",
    );
    expect(mockedDeleteScan).toHaveBeenCalledWith("scan-abc12345-def");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete scan" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
  });

  it("shows new scan dialog when button is clicked", async () => {
    mockedFetchScanPage.mockResolvedValue(scanPage(mockScans));

    render(<ScanManager />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("scan-abc")).toBeInTheDocument();
    });

    const newScanButton = screen.getByRole("button", { name: /new scan/i });
    fireEvent.click(newScanButton);

    await waitFor(() => {
      expect(
        screen.getByText(
          /agenthound scan --host-id <host-id> --network-realm-id <network-realm-id> --config/i,
        ),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText(
        /agenthound scan --host-id <host-id> --network-realm-id <network-realm-id> --output agenthound-scan\.json && agenthound-server ingest agenthound-scan\.json/i,
      ),
    ).toBeInTheDocument();
    const collectorCommands = screen
      .getAllByText(/^agenthound scan /i)
      .map((element) => element.textContent ?? "");
    expect(collectorCommands).toHaveLength(5);
    for (const command of collectorCommands) {
      expect(command).toContain("--host-id <host-id>");
      expect(command).toContain("--network-realm-id <network-realm-id>");
    }
    expect(
      screen.getByText(/They are provenance labels, not credentials\./i),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/\| agenthound-server ingest/),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/A2A requires the separate targeted command/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/fetch A2A cards/i)).not.toBeInTheDocument();

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveClass("max-h-[calc(100vh-2rem)]", "overflow-y-auto");

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
  });
});

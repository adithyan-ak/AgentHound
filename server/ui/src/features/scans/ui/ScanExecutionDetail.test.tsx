import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { fetchScan } from "@entities/scan/api";
import type { Scan } from "@entities/scan";
import { ScanHistory } from "./ScanHistory";

vi.mock("@entities/scan/api", async (importOriginal) => ({
  ...await importOriginal<typeof import("@entities/scan/api")>(),
  fetchScan: vi.fn(),
}));

const scan: Scan = {
  id: "scan-detail", collector: "scan", status: "completed", started_at: "2026-09-10T00:00:00Z",
  submitted: { nodes: 0, edges: 0 }, write_rows: { nodes: 0, edges: 0 },
  graph_totals: { before: null, after: null },
};
const detail: Scan = {
  ...scan,
  metadata: {
    collection_identity: { collection_point_id: "point-1", network_context_id: "network-1" },
    artifact_extra: { scan_execution: {
      version: 1, status: "completed", updated_at: "2026-09-10T00:01:00Z",
      actions: [{ id: "action-1", action: "test-action", status: "failed", target_id: "target-1", outcome: "failed", error: "recorded action error", recovery_id: "recovery-1" }],
      recovery: [{ id: "recovery-1", action_id: "action-1", action: "test-action", status: "conflict", error: "recorded recovery error", data: { secret: "private recovery payload" } }],
    } },
  },
};

function renderHistory() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter><ScanHistory scans={[scan]} /></MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.mocked(fetchScan).mockReset());

it("loads diagnosis only when opened and keeps recovery payloads out of the view", async () => {
  let resolve!: (value: Scan) => void;
  vi.mocked(fetchScan).mockReturnValue(new Promise((done) => { resolve = done; }));
  renderHistory();
  expect(fetchScan).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "View execution details for scan scan-detail" }));
  expect(screen.getByRole("status")).toHaveTextContent("Loading execution details");
  await act(async () => resolve(detail));
  const dialog = screen.getByRole("dialog");
  expect(await within(dialog).findByText(/Collection point: point-1/)).toHaveTextContent("Network context: network-1");
  expect(within(dialog).getByText(/Target: target-1/)).toHaveTextContent("Action ID: action-1");
  expect(within(dialog).getByRole("alert")).toHaveTextContent("1 unresolved cleanup records");
  expect(within(dialog).getByText("recorded action error")).not.toBeVisible();
  fireEvent.click(within(dialog).getAllByText("Reveal recorded error")[0]!);
  expect(within(dialog).getByText("recorded action error")).toBeVisible();
  expect(within(dialog).queryByText(/private recovery payload/)).not.toBeInTheDocument();
  expect(fetchScan).toHaveBeenCalledExactlyOnceWith("scan-detail");
});

it("offers retry after a detail read fails, then shows missing journal honestly", async () => {
  vi.mocked(fetchScan).mockRejectedValueOnce(new Error("network failure"));
  renderHistory();
  fireEvent.click(screen.getByRole("button", { name: "View execution details for scan scan-detail" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("could not be refreshed");
  vi.mocked(fetchScan).mockResolvedValueOnce(scan);
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await waitFor(() => expect(screen.getByText("Full execution journal unavailable for this scan.")).toBeInTheDocument());
  expect(screen.queryByText(/unresolved cleanup records/)).not.toBeInTheDocument();
});

it("does not recommend recovery for restored records", async () => {
  vi.mocked(fetchScan).mockResolvedValue({
    ...scan,
    metadata: { artifact_extra: { scan_execution: {
      version: 1, status: "completed", actions: [],
      recovery: [{ id: "restored-1", action_id: "action-1", action: "test-action", status: "restored" }],
    } } },
  });
  renderHistory();
  fireEvent.click(screen.getByRole("button", { name: "View execution details for scan scan-detail" }));
  expect(await screen.findByText("test-action · restored")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@entities/finding/model";

const mocks = vi.hoisted(() => ({
  useFindings: vi.fn(),
  mutate: vi.fn(),
}));

vi.mock("@entities/finding", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@entities/finding")>();
  return {
    ...actual,
    useFindings: mocks.useFindings,
    useSetTriage: () => ({ mutate: mocks.mutate }),
  };
});

import { FindingsListPage } from "./FindingsListPage";

const currentScope = {
  mode: "published",
  scanId: "scan-1",
  revision: 3,
  publishedAt: "2026-07-11T00:00:00Z",
  projectionStatus: "complete",
  snapshotStatus: "complete",
  available: true,
  stale: false,
};

function renderPage(initialEntry = "/findings") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <FindingsListPage />
    </MemoryRouter>,
  );
}

function finding(id: string, severity: string): Finding {
  return {
    id,
    severity,
    category: "Test",
    title: `${severity} finding`,
    description: `${severity} test finding`,
    edge_kind: "CAN_REACH",
    source_id: `source-${id}`,
    source_name: `Source ${id}`,
    source_kind: "AgentInstance",
    target_id: `target-${id}`,
    target_name: `Target ${id}`,
    target_kind: "MCPResource",
    confidence: 0.9,
    variant: "default",
    evidence: { state: "inferred" },
    owasp_map: [],
    atlas_map: [],
  };
}

describe("FindingsListPage request and snapshot states", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Element.prototype.scrollIntoView = vi.fn();
  });

  it("withholds the empty verdict after a cold request failure", () => {
    mocks.useFindings.mockReturnValue({
      data: undefined,
      snapshot: undefined,
      isLoading: false,
      isError: true,
      dataUpdatedAt: 0,
    });
    renderPage();
    expect(screen.getByRole("alert")).toHaveTextContent("Findings unavailable");
    expect(screen.getAllByText("--").length).toBeGreaterThan(0);
    expect(screen.queryByText(/No findings detected/i)).not.toBeInTheDocument();
  });

  it("claims an empty current snapshot only from explicit headers", () => {
    mocks.useFindings.mockReturnValue({
      data: [],
      snapshot: currentScope,
      isLoading: false,
      isError: false,
      dataUpdatedAt: Date.now(),
    });
    renderPage();
    expect(
      screen.getByText("No findings detected in the current published snapshot"),
    ).toBeInTheDocument();
  });

  it("labels cached data when a refresh fails", () => {
    mocks.useFindings.mockReturnValue({
      data: [],
      snapshot: currentScope,
      isLoading: false,
      isError: true,
      dataUpdatedAt: Date.parse("2026-07-11T00:00:00Z"),
    });
    renderPage();
    expect(screen.getByText("Showing cached findings")).toBeInTheDocument();
    expect(screen.getByText(/current status is unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/No findings detected in the current/i)).not.toBeInTheDocument();
  });

  it("applies the critical and high severity route filter", () => {
    mocks.useFindings.mockReturnValue({
      data: [
        finding("critical", "critical"),
        finding("high", "high"),
        finding("medium", "medium"),
      ],
      snapshot: currentScope,
      isLoading: false,
      isError: false,
      dataUpdatedAt: Date.now(),
    });

    renderPage("/findings?sev=critical,high");

    expect(screen.getByText("critical finding")).toBeInTheDocument();
    expect(screen.getByText("high finding")).toBeInTheDocument();
    expect(screen.queryByText("medium finding")).not.toBeInTheDocument();
  });
});

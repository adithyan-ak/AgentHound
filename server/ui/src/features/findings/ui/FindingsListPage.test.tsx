import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

function renderPage() {
  return render(
    <MemoryRouter>
      <FindingsListPage />
    </MemoryRouter>,
  );
}

describe("FindingsListPage request and snapshot states", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
});

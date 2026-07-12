import type { ReactNode } from "react";
import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { APINode } from "@entities/graph/dto";

vi.mock("recharts", () => ({
  Cell: () => null,
  Pie: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
  PieChart: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
  ResponsiveContainer: ({ children }: { children?: ReactNode }) => (
    <div>{children}</div>
  ),
  Tooltip: () => null,
}));

vi.mock("@entities/node", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@entities/node")>();
  return { ...actual, useNodes: vi.fn() };
});

vi.mock("@entities/prebuilt", () => ({
  usePreBuiltResult: vi.fn(),
}));

import { useNodes } from "@entities/node";
import { usePreBuiltResult } from "@entities/prebuilt";
import { AuthCoverage } from "./AuthCoverage";
import { Chokepoints } from "./Chokepoints";

const mockedUseNodes = vi.mocked(useNodes);
const mockedUsePreBuiltResult = vi.mocked(usePreBuiltResult);

function node(
  id: string,
  properties: Record<string, unknown>,
): APINode {
  return { id, kinds: ["MCPServer"], properties };
}

describe("dashboard authentication evidence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("separates local and unverified auth from confirmed anonymous access", () => {
    mockedUseNodes.mockReturnValue({
      data: [
        node("anonymous", {
          auth_method: "none",
          auth_evidence: "anonymous_probe_succeeded",
        }),
        node("stdio-local", {
          auth_method: "none",
          auth_evidence: "local_process",
        }),
        node("unverified", {
          auth_method: "none",
          auth_evidence: "unknown",
        }),
      ],
      isLoading: false,
    } as ReturnType<typeof useNodes>);

    render(<AuthCoverage />);

    expect(within(screen.getByText("None").closest("li")!).getByText("1"))
      .toBeInTheDocument();
    expect(
      within(screen.getByText("Local Process").closest("li")!).getByText("1"),
    ).toBeInTheDocument();
    expect(within(screen.getByText("Unknown").closest("li")!).getByText("1"))
      .toBeInTheDocument();
  });

  it("shows a chokepoint unauth badge only with affirmative evidence", () => {
    mockedUsePreBuiltResult.mockReturnValue({
      data: {
        rows: [
          {
            server_name: "confirmed-anonymous",
            agent_count: 4,
            tool_count: 2,
            auth_method: "none",
            auth_evidence: "anonymous_probe_succeeded",
          },
          {
            server_name: "stdio-local",
            agent_count: 3,
            tool_count: 1,
            auth_method: "none",
            auth_evidence: "local_process",
          },
          {
            server_name: "unverified-none",
            agent_count: 2,
            tool_count: 1,
            auth_method: "none",
            auth_evidence: "unknown",
          },
        ],
      },
      isLoading: false,
      isError: false,
    } as unknown as ReturnType<typeof usePreBuiltResult>);

    render(<Chokepoints />);

    expect(screen.getAllByText("unauth")).toHaveLength(1);
    expect(
      within(screen.getByText("confirmed-anonymous").closest("li")!)
        .getByText("unauth"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByText("stdio-local").closest("li")!)
        .queryByText("unauth"),
    ).not.toBeInTheDocument();
    expect(
      within(screen.getByText("unverified-none").closest("li")!)
        .queryByText("unauth"),
    ).not.toBeInTheDocument();
  });
});

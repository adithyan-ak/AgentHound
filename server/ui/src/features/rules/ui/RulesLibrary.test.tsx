import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { RulesLibrary } from "./RulesLibrary";

vi.mock("@entities/rule", () => ({
  useRules: () => ({
    data: { rules: [], total: 0 },
    isLoading: false,
    isError: false,
    error: null,
    dataUpdatedAt: Date.parse("2026-07-11T00:00:00Z"),
  }),
}));

vi.mock("@entities/scan", () => ({
  useScan: (id: string | null) => ({
    data:
      id === "older-scan"
        ? {
            id: "older-scan",
            collector: "config",
            status: "completed",
            started_at: "2026-06-01T00:00:00Z",
            completed_at: "2026-06-01T00:01:00Z",
            submitted: { nodes: 1, edges: 1 },
            write_rows: { nodes: 1, edges: 1 },
            graph_totals: { before: null, after: null },
            publication_status: "superseded",
            metadata: {
              ruleset: {
                digest: "sha256:older-effective-rules",
                load_state: "partial",
                authenticity: "unverified",
                entries: [
                  {
                    type: "text",
                    id: "older-custom-rule",
                    version: 7,
                    semantic_sha256: "sha256:older-custom-rule",
                    source: "custom",
                    effective_matcher: {
                      type: "keyword",
                      keywords: ["older-match"],
                    },
                  },
                ],
                errors: ["parse custom rule broken.yaml"],
              },
            },
          }
        : undefined,
    isLoading: false,
    isError: false,
    error: null,
  }),
  useScans: () => ({
    data: [
      {
        id: "scan-with-rules",
        collector: "mcp",
        status: "completed",
        started_at: "2026-07-11T00:00:00Z",
        completed_at: "2026-07-11T00:01:00Z",
        submitted: { nodes: 1, edges: 1 },
        write_rows: { nodes: 1, edges: 1 },
        graph_totals: { before: null, after: null },
        publication_status: "published",
        metadata: {
          ruleset: {
            digest: "sha256:effective-rules",
            load_state: "complete",
            authenticity: "unverified",
            entries: [
              {
                type: "text",
                id: "custom-rule",
                version: 2,
                semantic_sha256: "sha256:custom-rule",
                source: "custom",
                effective_matcher: {
                  type: "regex",
                  pattern: "effective",
                },
              },
            ],
            errors: [],
          },
        },
      },
    ],
    isLoading: false,
    isError: false,
    error: null,
  }),
}));

describe("RulesLibrary", () => {
  it("shows scan-specific provenance separately from current server rules", () => {
    render(
      <MemoryRouter>
        <RulesLibrary />
      </MemoryRouter>,
    );

    expect(screen.getByText("Scan evidence provenance")).toBeInTheDocument();
    expect(screen.getByText("unverified")).toBeInTheDocument();
    expect(screen.getByText("sha256:effective-rules")).toBeInTheDocument();
    expect(screen.getByText("Current server catalog")).toBeInTheDocument();
    expect(
      screen.getByText(/may differ from the selected scan/i),
    ).toBeInTheDocument();
  });

  it("loads a requested scan directly when it is older than the list page", () => {
    render(
      <MemoryRouter initialEntries={["/rules?scan=older-scan"]}>
        <RulesLibrary />
      </MemoryRouter>,
    );

    expect(
      screen.getByText("sha256:older-effective-rules"),
    ).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /older-scan/i })).toHaveValue(
      "older-scan",
    );
    expect(screen.getByText("parse custom rule broken.yaml")).toBeInTheDocument();
    expect(
      screen.getAllByText("Effective matcher definition").length,
    ).toBeGreaterThan(0);
  });
});

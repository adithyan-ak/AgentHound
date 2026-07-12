import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { QueryResult } from "../QueryResult";
import type { PreBuiltQuery } from "@entities/prebuilt/api";

const query: PreBuiltQuery = {
  id: "q1",
  name: "Test Query",
  description: "",
  category: "topology",
  severity: "info",
};

describe("QueryResult", () => {
  it("recursively renders nested object/array cell values instead of JSON blobs", () => {
    const rows = [
      {
        agent: "planner",
        path: [
          { name: "toolA", kind: "MCPTool" },
          { name: "resourceB", kind: "MCPResource" },
        ],
      },
    ];
    render(<QueryResult rows={rows} query={query} />);
    // Nested object keys/values are rendered as a tree, not `[object Object]`
    // or a raw JSON string.
    expect(screen.getByText("planner")).toBeInTheDocument();
    expect(screen.getByText("toolA")).toBeInTheDocument();
    expect(screen.getByText("resourceB")).toBeInTheDocument();
    expect(screen.queryByText(/\[object Object\]/)).not.toBeInTheDocument();
    expect(screen.queryByText(/\{"name"/)).not.toBeInTheDocument();
  });

  it("renders an empty-state message when there are no rows", () => {
    render(<QueryResult rows={[]} query={query} />);
    expect(screen.getByText(/no results for/i)).toBeInTheDocument();
  });

  it("joins arrays of primitives on one line", () => {
    render(
      <QueryResult
        rows={[{ tags: ["a", "b", "c"] }]}
        query={query}
      />,
    );
    expect(screen.getByText("a, b, c")).toBeInTheDocument();
  });
});

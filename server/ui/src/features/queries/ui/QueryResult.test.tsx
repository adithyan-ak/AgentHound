import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { PreBuiltQuery } from "@entities/prebuilt/api";
import { QueryResult } from "./QueryResult";

const query: PreBuiltQuery = {
  id: "nested-evidence",
  name: "Nested Evidence",
  description: "Test query",
  category: "Tests",
  severity: "medium",
};

describe("QueryResult", () => {
  it("wraps complete structured values while keeping scalar cells compact", () => {
    const scalar = "compact scalar value";
    const { container } = render(
      <QueryResult
        query={query}
        rows={[
          {
            name: scalar,
            evidence: {
              command: "run",
              context: { runtime: "python", sandboxed: false },
            },
            resources: [
              { uri: "file:///sensitive/report.txt", sensitivity: "critical" },
              ["nested", "array"],
            ],
          },
        ]}
      />,
    );

    const scalarCell = screen.getByText(scalar).closest("td");
    expect(scalarCell).toHaveClass("max-w-[300px]", "truncate");

    const structuredValues = container.querySelectorAll("pre");
    expect(structuredValues).toHaveLength(2);
    expect(structuredValues[0]).toHaveClass(
      "whitespace-pre-wrap",
      "break-words",
    );
    expect(structuredValues[0]).toHaveTextContent('"command": "run"');
    expect(structuredValues[0]).toHaveTextContent('"runtime": "python"');
    expect(structuredValues[1]).toHaveTextContent(
      '"uri": "file:///sensitive/report.txt"',
    );
    expect(structuredValues[1]).toHaveTextContent('"nested"');
    for (const value of structuredValues) {
      expect(value.closest("td")).not.toHaveClass("truncate");
      expect(value.closest("td")).not.toHaveClass("max-w-[300px]");
    }

    expect(screen.getByRole("columnheader", { name: "evidence" }))
      .toHaveAttribute("scope", "col");
  });
});

describe("QueryResult nested values", () => {
  it("renders exfiltration sensitive_resources as structured content", () => {
    render(
      <QueryResult
        query={{
          id: "exfiltration-routes",
          name: "Data Exfiltration Routes",
          description: "test",
          category: "Critical Paths",
          severity: "critical",
        }}
        rows={[
          {
            sensitive_resources: [
              { uri: "postgres://prod", sensitivity: "critical" },
              { uri: "s3://backups", sensitivity: "high" },
            ],
          },
        ]}
      />,
    );

    expect(screen.getByText(/postgres:\/\/prod/)).toBeInTheDocument();
    expect(screen.getByText(/s3:\/\/backups/)).toBeInTheDocument();
    expect(screen.queryByText(/\[object Object\]/)).not.toBeInTheDocument();
  });
});

describe("QueryResult traversal completeness", () => {
  const metadata = {
    scope: "security" as const,
    direction: "out" as const,
    relationshipKinds: ["TRUSTS_SERVER"],
    maxHops: 10,
    algorithm: "bounded-min-weight",
    complete: false,
    truncated: true,
    expansionLimit: 100,
    expansions: 101,
    incompleteReason: "expansion limit reached",
  };

  it("does not make an authoritative empty claim for incomplete traversal", () => {
    render(<QueryResult query={query} rows={[]} metadata={metadata} />);

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Traversal result is incomplete",
    );
    expect(screen.getByText(/Result unavailable/)).toBeInTheDocument();
    expect(screen.queryByText(/No results for/)).not.toBeInTheDocument();
  });

  it("renders the truncation warning before the returned row count", () => {
    render(
      <QueryResult
        query={query}
        rows={[{ name: "limited" }]}
        metadata={{ ...metadata, incompleteReason: "result limit reached" }}
      />,
    );

    const warning = screen.getByRole("alert");
    const count = screen.getByText("1 row");
    expect(
      warning.compareDocumentPosition(count) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(warning).toHaveTextContent("result limit reached");
  });
});

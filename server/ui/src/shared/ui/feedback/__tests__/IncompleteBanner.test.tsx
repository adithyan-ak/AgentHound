import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { IncompleteBanner } from "../IncompleteBanner";
import type { Completeness } from "@shared/api/page";

const complete: Completeness = {
  complete: true,
  coverage_status: "complete",
  generation_ids: ["g1"],
  truncated: false,
};

describe("IncompleteBanner", () => {
  it("renders nothing for a complete, healthy view", () => {
    const { container } = render(
      <IncompleteBanner completeness={complete} health={{ neo4j: "ok", postgres: "ok" }} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("discloses partial coverage", () => {
    render(<IncompleteBanner completeness={{ ...complete, complete: false, coverage_status: "partial" }} />);
    expect(screen.getByRole("status")).toHaveTextContent(/not authoritative/i);
    expect(screen.getByText(/partial coverage/i)).toBeInTheDocument();
  });

  it("discloses a degraded component from the health map", () => {
    render(
      <IncompleteBanner
        completeness={complete}
        health={{ neo4j: "ok", postgres: "unavailable" }}
      />,
    );
    expect(screen.getByText(/postgres \(unavailable\)/i)).toBeInTheDocument();
  });

  it("discloses truncation and source errors", () => {
    render(
      <IncompleteBanner
        completeness={{
          ...complete,
          truncated: true,
          source_errors: ["mcp: connection refused"],
        }}
      />,
    );
    expect(screen.getByText(/truncated/i)).toBeInTheDocument();
    expect(screen.getByText(/connection refused/i)).toBeInTheDocument();
  });
});

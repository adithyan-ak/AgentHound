import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { TopFindings } from "./TopFindings";

vi.mock("@entities/finding", () => ({
  useFindings: () => ({
    data: [],
    isLoading: false,
  }),
}));

describe("TopFindings", () => {
  it("links Critical Alerts to critical and high findings", () => {
    render(
      <MemoryRouter>
        <TopFindings />
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: /view all/i })).toHaveAttribute(
      "href",
      "/findings?sev=critical,high",
    );
  });
});

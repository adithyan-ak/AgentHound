import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { NavBar } from "./NavBar";

vi.mock("@entities/health", () => ({
  useHealth: () => ({
    data: { status: "ok", neo4j: "ok", postgres: "ok" },
    isError: false,
  }),
}));

describe("NavBar responsive access", () => {
  it("keeps every route accessible when compact labels are hidden", () => {
    render(
      <MemoryRouter>
        <NavBar />
      </MemoryRouter>,
    );

    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(nav).toHaveClass("overflow-x-auto");

    for (const label of [
      "Dashboard",
      "Explorer",
      "Findings",
      "Scans",
      "Queries",
      "Rules",
    ]) {
      const link = screen.getByRole("link", { name: label });
      expect(link).toHaveAttribute("title", label);
      expect(link.querySelector("span")).toHaveClass("hidden", "sm:inline");
    }
  });
});

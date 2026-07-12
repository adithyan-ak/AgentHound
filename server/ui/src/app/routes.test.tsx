import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppRoutes, NotFoundPage } from "./routes";

vi.mock("@entities/health", () => ({
  useHealth: () => ({
    data: { status: "ok", neo4j: "ok", postgres: "ok" },
    isError: false,
  }),
}));

describe("NotFoundPage", () => {
  it("renders an explicit recovery route", () => {
    render(
      <MemoryRouter>
        <NotFoundPage />
      </MemoryRouter>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Route not found");
    expect(
      screen.getByRole("link", { name: /return to dashboard/i }),
    ).toHaveAttribute("href", "/");
  });

  it("routes unknown URLs to the explicit fallback", () => {
    render(
      <MemoryRouter initialEntries={["/unknown/path"]}>
        <AppRoutes />
      </MemoryRouter>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Route not found");
  });
});

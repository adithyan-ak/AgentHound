import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CategoryBreakdown } from "./CategoryBreakdown";

vi.mock("@entities/finding", () => ({
  useFindings: () => ({
    data: [],
    isLoading: false,
  }),
}));

describe("CategoryBreakdown", () => {
  it("describes an empty category set as observed", () => {
    render(<CategoryBreakdown />);

    expect(screen.getByText("No findings observed yet")).toBeInTheDocument();
  });
});

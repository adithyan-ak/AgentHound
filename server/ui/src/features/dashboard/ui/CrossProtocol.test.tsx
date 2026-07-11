import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CrossProtocol } from "./CrossProtocol";

vi.mock("@entities/prebuilt", () => ({
  usePreBuiltResult: () => ({
    data: {
      rows: [
        {
          source_name: "external-agent",
          via_host: "shared-host",
          target_resource: "sensitive-resource",
        },
      ],
    },
    isLoading: false,
    isError: false,
  }),
}));

describe("CrossProtocol hypothesis presentation", () => {
  it("uses the medium hypothesis treatment instead of a critical-path alert", () => {
    render(<CrossProtocol />);

    expect(screen.getByText("Cross-Protocol Hypotheses")).toBeInTheDocument();
    const status = screen.getByText("Top 1 of 1 hypotheses");
    expect(status).toHaveClass("text-yellow-300");
    expect(status).not.toHaveClass("text-red-400");
  });
});

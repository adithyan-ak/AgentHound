import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { AttackCostMeter } from "../AttackCostMeter";

describe("AttackCostMeter", () => {
  it("renders UNKNOWN (not a fabricated 0) when the weight is null", () => {
    render(<AttackCostMeter totalWeight={null} missingCount={2} />);
    expect(screen.getByText(/unknown/i)).toBeInTheDocument();
    // Never presents a null cost as a trivial numeric value.
    expect(screen.queryByText(/\(0\.0\)/)).not.toBeInTheDocument();
  });

  it("renders LOW for a cheap (easy) attack path", () => {
    render(<AttackCostMeter totalWeight={0.2} />);
    expect(screen.getByText("LOW")).toBeInTheDocument();
    expect(screen.getByText("(0.2)")).toBeInTheDocument();
  });

  it("renders HIGH for an expensive path", () => {
    render(<AttackCostMeter totalWeight={2.5} />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });
});

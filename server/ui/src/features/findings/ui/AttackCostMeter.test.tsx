import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AttackCostMeter } from "./AttackCostMeter";

describe("AttackCostMeter completeness", () => {
  it("does not turn a missing weight into LOW (0.0)", () => {
    render(
      <AttackCostMeter
        cost={{
          state: "incomplete",
          value: null,
          reasons: ["missing_risk_weight"],
          missing_weight_edge_indexes: [1],
        }}
      />,
    );
    expect(screen.getByText("Incomplete")).toBeInTheDocument();
    expect(screen.getByText("(1 unweighted)")).toBeInTheDocument();
    expect(screen.queryByText("LOW")).not.toBeInTheDocument();
  });

  it("shows non-linear cost as not applicable", () => {
    render(
      <AttackCostMeter
        cost={{
          state: "not_applicable",
          value: null,
          reasons: ["non_linear_evidence"],
          missing_weight_edge_indexes: [],
        }}
      />,
    );
    expect(screen.getByText("Not applicable")).toBeInTheDocument();
    expect(screen.queryByText("LOW")).not.toBeInTheDocument();
  });
});

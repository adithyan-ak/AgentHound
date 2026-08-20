import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FindingProof } from "./FindingProof";

describe("FindingProof", () => {
  it("renders the complete read-only proof contract", () => {
    render(
      <FindingProof
        evidence={{
          state: "verified",
          channels: [],
          proof: {
            action: "credential_reach",
            action_id: "action-ui",
            verified_at: "2026-07-13T12:00:00Z",
            proof_type: "differential_resource_read",
            outcome: "credential_required",
            control_stage: "initialize",
            control_status: "denied",
            control_resource_addressed: false,
            credential_stage: "resource_read",
            credential_status: "allowed",
            credential_resource_addressed: true,
            cleanup_status: "not_applicable",
          },
        }}
      />,
    );

    expect(screen.getByText("Access Proof")).toBeInTheDocument();
    expect(screen.getByText("action-ui")).toBeInTheDocument();
    expect(
      screen.getByText("initialize · denied · resource not addressed"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("resource_read · allowed · resource addressed"),
    ).toBeInTheDocument();
    expect(screen.getByText("not_applicable")).toBeInTheDocument();
    expect(
      screen.getByText(/not agent invocation or downstream impact/i),
    ).toBeInTheDocument();
  });
});

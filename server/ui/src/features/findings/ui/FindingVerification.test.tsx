import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FindingVerification } from "./FindingVerification";

describe("FindingVerification", () => {
  it("renders the complete read-only verification contract", () => {
    render(
      <FindingVerification
        evidence={{
          state: "verified",
          channels: [],
          verification: {
            scenario_id: "cred-reach",
            scenario_version: 1,
            campaign_run_id: "run-ui",
            verified_at: "2026-07-13T12:00:00Z",
            oracle_type: "differential_credential_reach",
            outcome: "credential_gated_reach_verified",
            control_stage: "initialize",
            control_status: "denied",
            control_resource_addressed: false,
            authed_stage: "resource_read",
            authed_status: "allowed",
            authed_resource_addressed: true,
            cleanup_status: "not_applicable",
          },
        }}
      />,
    );

    expect(screen.getByText("Campaign Verification")).toBeInTheDocument();
    expect(screen.getByText("cred-reach v1")).toBeInTheDocument();
    expect(screen.getByText("run-ui")).toBeInTheDocument();
    expect(screen.getByText("initialize · denied · resource not addressed")).toBeInTheDocument();
    expect(screen.getByText("resource_read · allowed · resource addressed")).toBeInTheDocument();
    expect(screen.getByText("not_applicable")).toBeInTheDocument();
    expect(screen.getByText(/not agent invocation or impact/i)).toBeInTheDocument();
  });
});

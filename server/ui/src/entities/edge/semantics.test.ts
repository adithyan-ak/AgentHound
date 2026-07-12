import { describe, expect, it } from "vitest";
import { edgeDescription, edgeLabel } from "./semantics";

describe("EXPOSES_CREDENTIAL semantics", () => {
  it.each([
    { assertion_type: "observed_credential_exposure" },
    { exposure_status: "exposed" },
    {
      assertion_type: "credential_reference",
      exposure_status: "exposed",
    },
  ])("describes observed exposure from available evidence", (properties) => {
    const context = { properties };

    expect(edgeLabel("EXPOSES_CREDENTIAL", context)).toBe(
      "OBSERVED CREDENTIAL EXPOSURE",
    );
    expect(edgeDescription("EXPOSES_CREDENTIAL", context)).toBe(
      "AI service exposes observed credential material",
    );
    expect(edgeDescription("EXPOSES_CREDENTIAL", context)).not.toMatch(
      /merely|reference/i,
    );
  });

  it.each([
    { assertion_type: "credential_reference" },
    { exposure_status: "not_observed" },
  ])("describes reference-only evidence without claiming exposure", (properties) => {
    const context = { properties };

    expect(edgeLabel("EXPOSES_CREDENTIAL", context)).toBe(
      "CREDENTIAL REFERENCE",
    );
    expect(edgeDescription("EXPOSES_CREDENTIAL", context)).toMatch(
      /credential reference.*not observed/i,
    );
  });

  it("uses neutral wording when evidence properties are unavailable", () => {
    expect(edgeLabel("EXPOSES_CREDENTIAL")).toBe("CREDENTIAL EVIDENCE");
    expect(edgeDescription("EXPOSES_CREDENTIAL")).toBe(
      "AI service has credential evidence",
    );
  });
});

describe("CAN_REACH target semantics", () => {
  it("uses neutral wording without a target kind", () => {
    expect(edgeDescription("CAN_REACH")).toBe("Agent can reach target");
  });

  it("names credential and resource targets accurately", () => {
    expect(
      edgeDescription("CAN_REACH", { targetKind: "Credential" }),
    ).toBe("Agent can reach credential");
    expect(
      edgeDescription("CAN_REACH", { targetKind: "MCPResource" }),
    ).toBe("Agent can reach resource");
  });
});

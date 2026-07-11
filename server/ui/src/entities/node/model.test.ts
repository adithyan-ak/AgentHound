import { describe, expect, it } from "vitest";
import type { APINode } from "@entities/graph/dto";
import {
  authMethod,
  hasConfirmedAnonymousAccess,
  isCredentialExposed,
  isUnauth,
  riskAssessment,
  riskScore,
} from "./model";

function node(properties: Record<string, unknown>, kinds = ["MCPServer"]): APINode {
  return { id: "node-1", kinds, properties };
}

describe("node evidence accessors", () => {
  it("requires affirmative evidence and normalizes legacy local processes", () => {
    const unknown = node({});
    const unsupportedClaim = node({ auth_method: "none", auth_evidence: "unknown" });
    const local = node({
      auth_method: "unknown",
      auth_evidence: "local_process",
    });
    const legacyLocal = node({
      auth_method: "none",
      auth_evidence: "local_process",
    });
    const anonymous = node({
      auth_method: "none",
      auth_evidence: "anonymous_probe_succeeded",
    });
    expect(authMethod(unknown)).toBe("unknown");
    expect(isUnauth(unknown)).toBe(false);
    expect(authMethod(unsupportedClaim)).toBe("unknown");
    expect(isUnauth(unsupportedClaim)).toBe(false);
    expect(authMethod(local)).toBe("localProcess");
    expect(authMethod(legacyLocal)).toBe("localProcess");
    expect(hasConfirmedAnonymousAccess(legacyLocal.properties)).toBe(false);
    expect(authMethod(anonymous)).toBe("none");
    expect(isUnauth(anonymous)).toBe(true);
  });

  it("does not turn a missing risk assessment into zero", () => {
    expect(riskScore(node({}))).toBeNull();
    expect(riskAssessment(node({}))).toEqual({
      score: null,
      min: null,
      max: null,
      complete: false,
      unknownFactors: [],
    });
    expect(riskAssessment(node({ risk_score: 42 })).complete).toBe(false);
  });

  it("excludes masked and hashed credential references from exposure", () => {
    expect(
      isCredentialExposed(
        node(
          {
            merge_key: "identity",
            material_status: "masked",
            exposure_status: "not_observed",
            is_exposed: true,
          },
          ["Credential"],
        ),
      ),
    ).toBe(false);
    expect(
      isCredentialExposed(
        node(
          {
            merge_key: "value_hash",
            material_status: "observed",
            exposure_status: "exposed",
          },
          ["Credential"],
        ),
      ),
    ).toBe(true);
    expect(
      isCredentialExposed(
        node(
          {
            merge_key: "value_hash",
            is_exposed: true,
            type: "hardcoded",
          },
          ["Credential"],
        ),
      ),
    ).toBe(false);
  });
});

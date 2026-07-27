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
  it("requires affirmative evidence and renders local processes", () => {
    const unknown = node({});
    const unsupportedClaim = node({ auth_method: "none", auth_evidence: "unknown" });
    const local = node({
      effective_auth_method: "unknown",
      effective_auth_assurance: "unknown",
      effective_auth_evidence: "local_process",
      effective_auth_source: "configured",
    });
    const configuredLocal = node({
      effective_auth_method: "none",
      effective_auth_assurance: "unknown",
      effective_auth_evidence: "local_process",
      effective_auth_source: "configured",
    });
    const unprovenRawAnonymous = node({
      auth_method: "none",
      auth_assurance: "unauthenticated",
      auth_evidence: "anonymous_probe_succeeded",
    });
    expect(authMethod(unknown)).toBe("unknown");
    expect(isUnauth(unknown)).toBe(false);
    expect(authMethod(unsupportedClaim)).toBe("unknown");
    expect(isUnauth(unsupportedClaim)).toBe(false);
    expect(authMethod(local)).toBe("localProcess");
    expect(authMethod(configuredLocal)).toBe("localProcess");
    expect(hasConfirmedAnonymousAccess(configuredLocal.properties)).toBe(false);
    expect(authMethod(unprovenRawAnonymous)).toBe("unknown");
    expect(isUnauth(unprovenRawAnonymous)).toBe(false);
  });

  it("uses only the materialized effective auth tuple", () => {
    const rawObservedAnonymous = node({
      auth_method: "unknown",
      auth_assurance: "unknown",
      auth_evidence: "unknown",
      transport: "http",
      status: "reachable",
      observed_auth_method: "none",
      observed_auth_assurance: "unauthenticated",
      observed_auth_evidence: "anonymous_probe_succeeded",
    });
    const rawConfiguredBearer = node({
      auth_method: "bearer",
      auth_assurance: "moderate",
      auth_evidence: "configured_credential",
      observed_auth_method: "unknown",
      observed_auth_assurance: "unknown",
      observed_auth_evidence: "unknown",
    });
    const materializedAnonymous = node({
      auth_method: "unknown",
      auth_evidence: "unknown",
      effective_auth_method: "none",
      effective_auth_assurance: "unauthenticated",
      effective_auth_evidence: "anonymous_probe_succeeded",
      effective_auth_source: "observed",
    });
    const materializedBearer = node({
      effective_auth_method: "bearer",
      effective_auth_assurance: "moderate",
      effective_auth_evidence: "configured_credential",
      effective_auth_source: "configured",
    });
    const configuredAnonymousClaim = node({
      auth_method: "none",
      auth_assurance: "unauthenticated",
      auth_evidence: "anonymous_probe_succeeded",
      effective_auth_method: "none",
      effective_auth_assurance: "unauthenticated",
      effective_auth_evidence: "anonymous_probe_succeeded",
      effective_auth_source: "configured",
    });
    const incompleteMaterialized = node({
      effective_auth_method: "none",
      effective_auth_source: "observed",
    });

    expect(authMethod(rawObservedAnonymous)).toBe("unknown");
    expect(isUnauth(rawObservedAnonymous)).toBe(false);
    expect(authMethod(rawConfiguredBearer)).toBe("unknown");
    expect(isUnauth(rawConfiguredBearer)).toBe(false);
    expect(authMethod(materializedAnonymous)).toBe("none");
    expect(isUnauth(materializedAnonymous)).toBe(true);
    expect(authMethod(materializedBearer)).toBe("bearer");
    expect(isUnauth(materializedBearer)).toBe(false);
    expect(authMethod(configuredAnonymousClaim)).toBe("unknown");
    expect(isUnauth(configuredAnonymousClaim)).toBe(false);
    expect(authMethod(incompleteMaterialized)).toBe("unknown");
    expect(isUnauth(incompleteMaterialized)).toBe(false);
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
            type: "hardcoded",
          },
          ["Credential"],
        ),
      ),
    ).toBe(false);
  });
});

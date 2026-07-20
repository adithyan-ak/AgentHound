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
      auth_method: "unknown",
      auth_evidence: "local_process",
    });
    const configuredLocal = node({
      auth_method: "none",
      auth_evidence: "local_process",
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

  it("selects one effective auth tuple with observed runtime precedence", () => {
    const observedAnonymous = node({
      auth_method: "unknown",
      auth_assurance: "unknown",
      auth_evidence: "unknown",
      transport: "http",
      status: "reachable",
      observed_auth_method: "none",
      observed_auth_assurance: "unauthenticated",
      observed_auth_evidence: "anonymous_probe_succeeded",
    });
    const configuredFallback = node({
      auth_method: "bearer",
      auth_assurance: "moderate",
      auth_evidence: "configured_credential",
      observed_auth_method: "unknown",
      observed_auth_assurance: "unknown",
      observed_auth_evidence: "unknown",
    });
    const observedBearer = node({
      auth_method: "none",
      auth_assurance: "unauthenticated",
      auth_evidence: "anonymous_probe_succeeded",
      observed_auth_method: "bearer",
      observed_auth_assurance: "moderate",
      observed_auth_evidence: "configured_credential",
    });
    const materialized = node({
      auth_method: "unknown",
      auth_evidence: "unknown",
      effective_auth_method: "none",
      effective_auth_assurance: "unauthenticated",
      effective_auth_evidence: "anonymous_probe_succeeded",
      effective_auth_source: "observed",
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
    const observedA2AAnonymous = node(
      {
        auth_probe_method: "get_task_nonexistent",
        auth_probe_status: "anonymous_protocol_access",
        auth_probe_detail: "task_not_found_v0_3",
        observed_auth_method: "none",
        observed_auth_assurance: "unauthenticated",
        observed_auth_evidence: "anonymous_probe_succeeded",
      },
      ["A2AAgent"],
    );
    const a2aMissingDetail = node(
      {
        auth_probe_method: "get_task_nonexistent",
        auth_probe_status: "anonymous_protocol_access",
        observed_auth_method: "none",
        observed_auth_assurance: "unauthenticated",
        observed_auth_evidence: "anonymous_probe_succeeded",
      },
      ["A2AAgent"],
    );

    expect(authMethod(observedAnonymous)).toBe("none");
    expect(isUnauth(observedAnonymous)).toBe(true);
    expect(authMethod(configuredFallback)).toBe("bearer");
    expect(isUnauth(configuredFallback)).toBe(false);
    expect(authMethod(observedBearer)).toBe("bearer");
    expect(isUnauth(observedBearer)).toBe(false);
    expect(authMethod(materialized)).toBe("none");
    expect(isUnauth(materialized)).toBe(true);
    expect(authMethod(configuredAnonymousClaim)).toBe("unknown");
    expect(isUnauth(configuredAnonymousClaim)).toBe(false);
    expect(authMethod(observedA2AAnonymous)).toBe("none");
    expect(isUnauth(observedA2AAnonymous)).toBe(true);
    expect(authMethod(a2aMissingDetail)).toBe("unknown");
    expect(isUnauth(a2aMissingDetail)).toBe(false);
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

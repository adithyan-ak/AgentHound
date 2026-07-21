import { describe, expect, it } from "vitest";
import { getPropertyChips } from "./property-chips";

describe("authentication property chips", () => {
  it("shows no-auth only for confirmed anonymous access", () => {
    expect(
      getPropertyChips("MCPServer", {
        transport: "http",
        auth_method: "none",
        auth_assurance: "unauthenticated",
        auth_evidence: "anonymous_probe_succeeded",
        effective_auth_method: "none",
        effective_auth_assurance: "unauthenticated",
        effective_auth_evidence: "anonymous_probe_succeeded",
        effective_auth_source: "observed",
      }),
    ).toContain("no-auth");

    expect(
      getPropertyChips("MCPServer", {
        transport: "http",
        auth_method: "none",
        auth_evidence: "unknown",
      }),
    ).toContain("auth-unknown");
  });

  it("renders canonical stdio local-process evidence", () => {
    const chips = getPropertyChips("MCPServer", {
      transport: "stdio",
      auth_method: "none",
      auth_evidence: "local_process",
    });

    expect(chips).toContain("local-process");
    expect(chips).not.toContain("no-auth");
  });

  it("renders observed anonymous access when configuration was unknown", () => {
    const chips = getPropertyChips("MCPServer", {
      transport: "http",
      status: "reachable",
      auth_method: "unknown",
      auth_evidence: "unknown",
      observed_auth_method: "none",
      observed_auth_assurance: "unauthenticated",
      observed_auth_evidence: "anonymous_probe_succeeded",
    });

    expect(chips).toContain("no-auth");
    expect(chips).not.toContain("auth-unknown");
  });
});

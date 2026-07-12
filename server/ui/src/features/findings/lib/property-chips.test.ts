import { describe, expect, it } from "vitest";
import { getPropertyChips } from "./property-chips";

describe("authentication property chips", () => {
  it("shows no-auth only for confirmed anonymous access", () => {
    expect(
      getPropertyChips("MCPServer", {
        transport: "http",
        auth_method: "none",
        auth_evidence: "anonymous_probe_succeeded",
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
});

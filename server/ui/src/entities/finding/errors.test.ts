import { describe, expect, it } from "vitest";
import { findingDetailErrorPresentation } from "./errors";

describe("finding detail error discrimination", () => {
  it("uses not-found copy only for HTTP 404", () => {
    const result = findingDetailErrorPresentation({
      response: { status: 404 },
    });
    expect(result.kind).toBe("not_found");
    expect(result.title).toBe("Finding not found");
  });

  it("does not describe service failures as resolved findings", () => {
    const result = findingDetailErrorPresentation({
      response: { status: 503 },
    });
    expect(result.kind).toBe("unavailable");
    expect(result.title).toBe("Finding detail unavailable");
    expect(result.message).toContain("No conclusion");
    expect(result.message).not.toContain("resolved in a recent scan");
  });

  it("treats non-HTTP failures as unavailable", () => {
    expect(findingDetailErrorPresentation(new Error("network down")).kind).toBe(
      "unavailable",
    );
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import { fetchHealth } from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

describe("fetchHealth", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("parses a degraded 503 body instead of retaining a prior all-clear", async () => {
    getMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          status: "degraded",
          neo4j: "unavailable",
          postgres: "ok",
        }),
        {
          status: 503,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    await expect(fetchHealth()).resolves.toEqual({
      status: "degraded",
      neo4j: "unavailable",
      postgres: "ok",
    });
    expect(getMock).toHaveBeenCalledWith("health", {
      throwHttpErrors: false,
    });
  });

  it("rejects an unexpected non-health HTTP failure", async () => {
    getMock.mockResolvedValue(
      new Response(JSON.stringify({ status: "unknown" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(fetchHealth()).rejects.toThrow(/status 500/);
  });
});

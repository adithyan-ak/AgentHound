import { beforeEach, describe, expect, it, vi } from "vitest";
import { fetchNodeCollection } from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

function pageResponse(
  body: unknown,
  {
    offset,
    total,
    hasMore,
    revision = "rev-1",
  }: { offset: number; total: number; hasMore: boolean; revision?: string },
): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Offset": String(offset),
      "X-Total-Count": String(total),
      "X-Has-More": String(hasMore),
      "X-Collection-Complete": String(!hasMore),
      "X-Revision": revision,
    },
  });
}

function node(id: string) {
  return { id, kinds: ["MCPServer"], properties: { name: id } };
}

describe("fetchNodeCollection", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("iterates every stable page and forwards the revision token", async () => {
    getMock
      .mockResolvedValueOnce(
        pageResponse([node("a"), node("b")], {
          offset: 0,
          total: 3,
          hasMore: true,
        }),
      )
      .mockResolvedValueOnce(
        pageResponse([node("c")], {
          offset: 2,
          total: 3,
          hasMore: false,
        }),
      );

    const result = await fetchNodeCollection(undefined, 2);

    expect(result.complete).toBe(true);
    expect(result.items.map((item) => item.id)).toEqual(["a", "b", "c"]);
    expect(getMock).toHaveBeenCalledTimes(2);
    expect(getMock.mock.calls[1]?.[1]?.searchParams).toMatchObject({
      offset: "2",
      revision: "rev-1",
    });
  });

  it("rejects malformed non-array responses instead of treating them as empty", async () => {
    getMock.mockResolvedValueOnce(
      pageResponse({}, { offset: 0, total: 0, hasMore: false }),
    );

    await expect(fetchNodeCollection()).rejects.toThrow(/must be an array/);
  });
});

import { describe, it, expect } from "vitest";
import {
  unwrapPage,
  isAuthoritative,
  NONE_COMPLETENESS,
  type Completeness,
  type Page,
} from "../page";

const complete: Completeness = {
  complete: true,
  coverage_status: "complete",
  generation_ids: ["g1"],
  truncated: false,
};

function page<T>(items: T[], c: Completeness): Page<T> {
  return { items, total: items.length, limit: 50, offset: 0, completeness: c };
}

describe("unwrapPage", () => {
  it("returns the items of a Page envelope", () => {
    expect(unwrapPage(page([1, 2, 3], complete))).toEqual([1, 2, 3]);
  });

  it("tolerates a bare array (legacy / fixture)", () => {
    expect(unwrapPage([1, 2])).toEqual([1, 2]);
  });

  it("returns [] for null/undefined and a missing items list", () => {
    expect(unwrapPage(null)).toEqual([]);
    expect(unwrapPage(undefined)).toEqual([]);
    expect(unwrapPage({ items: undefined } as unknown as Page<number>)).toEqual([]);
  });
});

describe("isAuthoritative", () => {
  it("is true only for a complete, error-free view", () => {
    expect(isAuthoritative(complete)).toBe(true);
  });

  it("is false for the default 'none' completeness", () => {
    expect(isAuthoritative(NONE_COMPLETENESS)).toBe(false);
    expect(isAuthoritative(undefined)).toBe(false);
  });

  it("is false when coverage is partial/failed/unknown even if complete flag set", () => {
    expect(
      isAuthoritative({ ...complete, complete: true, coverage_status: "partial" }),
    ).toBe(false);
  });

  it("is false when source errors are present", () => {
    expect(
      isAuthoritative({ ...complete, source_errors: ["mcp: connection refused"] }),
    ).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import {
  canonicalFindingGroup,
  canonicalizeFindingGroupParams,
} from "./grouping";

describe("finding group URL canonicalization", () => {
  it("accepts supported group values", () => {
    expect(canonicalFindingGroup("severity")).toBe("severity");
    expect(canonicalFindingGroup("edge_kind")).toBe("edge_kind");
  });

  it("uses the ungrouped view for an invalid value", () => {
    expect(canonicalFindingGroup("prototype")).toBe("none");
  });

  it("removes only the invalid group parameter", () => {
    const canonical = canonicalizeFindingGroupParams(
      new URLSearchParams("group=prototype&q=credential&sev=high"),
    );
    expect(canonical.get("group")).toBeNull();
    expect(canonical.get("q")).toBe("credential");
    expect(canonical.get("sev")).toBe("high");
  });
});

import { describe, it, expect } from "vitest";
import { EDGE_KINDS, EDGE_KIND_META } from "@entities/graph/dto";
import { edgeDescription, edgeLabel } from "@entities/edge";
import { isCompositeEdge } from "@entities/edge/styles";
import { LENS_LIST, lensForEdgeKind, getLens } from "../lens-config";

// The four non-special lenses (topology, attack-surface, credentials,
// poisoning) drive edge selection by kind; the rest (critical, cross-protocol,
// blast-radius, chokepoints) select edges at runtime and carry no edgeKinds.
const KIND_LENSES = ["topology", "attack-surface", "credentials", "poisoning"] as const;

describe("edge coverage — every one of the 32 edge kinds is handled", () => {
  it("has exactly 32 edge kinds", () => {
    expect(EDGE_KINDS).toHaveLength(32);
  });

  it("every edge kind has an honest, non-empty description", () => {
    for (const kind of EDGE_KINDS) {
      const desc = edgeDescription(kind);
      expect(desc, kind).toBeTruthy();
      // Every generated kind resolves to its metadata description (or a
      // hand-tuned override), never a bare underscore slug.
      expect(desc, kind).not.toContain("_");
    }
  });

  it("the kind-driven lenses collectively cover all 32 edge kinds (no orphan edges)", () => {
    const covered = new Set<string>();
    for (const lens of LENS_LIST) {
      if ((KIND_LENSES as readonly string[]).includes(lens.id)) {
        for (const k of lens.edgeKinds) covered.add(k);
      }
    }
    const all = new Set<string>(EDGE_KINDS);
    // Every supported edge renders in at least one lens.
    for (const kind of all) {
      expect(covered.has(kind), `edge ${kind} is not in any lens`).toBe(true);
    }
    // And no lens references an unknown edge kind.
    for (const kind of covered) {
      expect(all.has(kind), `lens references unknown edge ${kind}`).toBe(true);
    }
  });

  it("lensForEdgeKind routes each edge to a real lens matching its generated lens category", () => {
    for (const kind of EDGE_KINDS) {
      const lensId = lensForEdgeKind(kind);
      expect(() => getLens(lensId), kind).not.toThrow();
      // The deep-link lens matches the generated lens category for the kind.
      expect(lensId, kind).toBe(EDGE_KIND_META[kind].lens);
    }
  });

  it("composite-ness is derived from the generated metadata", () => {
    for (const kind of EDGE_KINDS) {
      expect(isCompositeEdge(kind), kind).toBe(EDGE_KIND_META[kind].composite);
    }
  });

  it("humanizes an unknown edge kind rather than throwing", () => {
    expect(edgeLabel("SOME_FUTURE_EDGE")).toBe("SOME FUTURE EDGE");
    expect(edgeDescription("SOME_FUTURE_EDGE")).toBe("SOME FUTURE EDGE");
  });
});

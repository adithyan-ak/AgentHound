import { describe, expect, it } from "vitest";
import { EDGE_KINDS } from "@entities/graph/dto";
import { EDGE_PRIMARY_LENS, getLens } from "../lens-config";

describe("edge lens parity", () => {
  it("routes every edge kind through a reachable primary lens preset", () => {
    for (const kind of EDGE_KINDS) {
      const lens = getLens(EDGE_PRIMARY_LENS[kind]);
      expect(lens.edgeKinds).toContain(kind);
      expect(lens.subPresets.map((preset) => preset.id)).toContain(kind);
    }
  });

  it("describes shared-host cross-protocol evidence as a hypothesis", () => {
    expect(getLens("cross-protocol").description).toMatch(
      /50%-confidence.*hypotheses.*not proven/i,
    );
  });
});

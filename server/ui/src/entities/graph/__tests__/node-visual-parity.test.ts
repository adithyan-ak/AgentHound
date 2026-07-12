import { describe, it, expect } from "vitest";
import { NODE_KINDS } from "../generated";
import { HEX_CONFIG, getHexConfig } from "@shared/lib/hex-config";
import { NODE_KIND_COLORS, NODE_KIND_COLORS_BY_KEY } from "@shared/theme/tokens";

// Guards parity between the canonical node-kind registry (generated from the Go
// source of truth) and the UI node visuals in shared/lib/hex-config. Lives in
// the entities/graph layer because it must see both the registry and shared.
describe("node kind visual parity", () => {
  it("provides a dedicated visual for every canonical node kind", () => {
    // No canonical kind may fall through to the generic FALLBACK hex, which
    // carries the "NODE" tag.
    for (const kind of NODE_KINDS) {
      expect(HEX_CONFIG, `missing HEX_CONFIG entry for ${kind}`).toHaveProperty(kind);
      expect(getHexConfig(kind).kindTag).not.toBe("NODE");
    }
  });

  it("gives ExtractedTrainingSignal a complete, distinct visual", () => {
    const cfg = getHexConfig("ExtractedTrainingSignal");
    expect(cfg.kindTag).toBe("TRAINING SIGNAL");
    expect(cfg.groupLabel).toBe("AI Models");
    expect(cfg.strokeColor).toBe(NODE_KIND_COLORS.ExtractedTrainingSignal);
    // Sits downstream of AIModel (col 3) per the EXTRACTED_FROM edge.
    expect(cfg.column).toBe(4);
    // Distinct from the deep AIModel purple it derives from.
    expect(cfg.strokeColor).not.toBe(NODE_KIND_COLORS.AIModel);
  });

  it("no longer registers the removed synthetic kinds", () => {
    for (const removed of ["ResourceGroup", "TrustZone"]) {
      expect(NODE_KINDS).not.toContain(removed);
      expect(HEX_CONFIG).not.toHaveProperty(removed);
      expect(NODE_KIND_COLORS_BY_KEY[removed]).toBeUndefined();
    }
  });
});

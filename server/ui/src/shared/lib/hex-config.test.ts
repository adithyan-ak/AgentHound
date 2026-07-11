import { describe, expect, it } from "vitest";
import { NODE_KIND_COLORS } from "@shared/theme/tokens";
import { getHexConfig } from "./hex-config";

describe("ExtractedTrainingSignal visual contract", () => {
  it("uses a dedicated signal visual instead of the generic node fallback", () => {
    const config = getHexConfig("ExtractedTrainingSignal");
    expect(config.kindTag).toBe("TRAINING SIGNAL");
    expect(config.groupLabel).toBe("Extracted Signals");
    expect(config.strokeColor).toBe(NODE_KIND_COLORS.ExtractedTrainingSignal);
  });
});

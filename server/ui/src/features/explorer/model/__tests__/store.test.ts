import { describe, expect, it } from "vitest";
import {
  DEFAULT_SUB_PRESETS,
  migrateExplorerState,
} from "../store";

describe("Explorer persisted preference migration", () => {
  it("advances version-1 default arrays to the current lens defaults", () => {
    const migrated = migrateExplorerState(
      {
        activeLens: "attack-surface",
        subPresets: {
          ...DEFAULT_SUB_PRESETS,
          "attack-surface": [
            "HAS_ACCESS_TO",
            "CAN_EXECUTE",
            "CAN_REACH",
            "CAN_EXFILTRATE_VIA",
            "CAN_IMPERSONATE",
          ],
          poisoning: [
            "POISONED_DESCRIPTION",
            "SHADOWS",
            "POISONED_INSTRUCTIONS",
          ],
        },
      },
      1,
    );

    expect(migrated.subPresets?.["attack-surface"]).toEqual(
      DEFAULT_SUB_PRESETS["attack-surface"],
    );
    expect(migrated.subPresets?.poisoning).toEqual(
      DEFAULT_SUB_PRESETS.poisoning,
    );
  });

  it("preserves deliberate version-1 sub-preset filters", () => {
    const migrated = migrateExplorerState(
      {
        activeLens: "attack-surface",
        subPresets: {
          ...DEFAULT_SUB_PRESETS,
          "attack-surface": ["CAN_REACH"],
          poisoning: [],
        },
      },
      1,
    );

    expect(migrated.subPresets?.["attack-surface"]).toEqual(["CAN_REACH"]);
    expect(migrated.subPresets?.poisoning).toEqual([]);
  });
});

import { create } from "zustand";
import { persist } from "zustand/middleware";

/**
 * Attack-graph marks store (shared kernel).
 *
 * Owned = attacker-controlled (red target); High Value = crown overlay. These
 * annotations are consumed across the Explorer canvas and context menu, so the
 * persisted slice remains in shared state.
 *
 * The persist key `agenthound-graph-marks` and the `partialize` shape are kept
 * byte-compatible with the legacy store so existing marks rehydrate unchanged.
 */
interface MarksState {
  ownedNodeIds: string[];
  highValueNodeIds: string[];
}

interface MarksActions {
  toggleOwned: (id: string) => void;
  toggleHighValue: (id: string) => void;
  isOwned: (id: string) => boolean;
  isHighValue: (id: string) => boolean;
}

type PersistedShape = {
  ownedNodeIds: string[];
  highValueNodeIds: string[];
};

export const useMarksStore = create<MarksState & MarksActions>()(
  persist(
    (set, get) => ({
      ownedNodeIds: [],
      highValueNodeIds: [],

      toggleOwned: (id) =>
        set((state) => {
          const exists = state.ownedNodeIds.includes(id);
          return {
            ownedNodeIds: exists
              ? state.ownedNodeIds.filter((x) => x !== id)
              : [...state.ownedNodeIds, id],
          };
        }),

      toggleHighValue: (id) =>
        set((state) => {
          const exists = state.highValueNodeIds.includes(id);
          return {
            highValueNodeIds: exists
              ? state.highValueNodeIds.filter((x) => x !== id)
              : [...state.highValueNodeIds, id],
          };
        }),

      isOwned: (id) => get().ownedNodeIds.includes(id),

      isHighValue: (id) => get().highValueNodeIds.includes(id),
    }),
    {
      name: "agenthound-graph-marks",
      partialize: (state): PersistedShape => ({
        ownedNodeIds: state.ownedNodeIds,
        highValueNodeIds: state.highValueNodeIds,
      }),
    },
  ),
);

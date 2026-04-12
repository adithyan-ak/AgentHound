import { create } from "zustand";

export type LensId =
  | "topology"
  | "attack-surface"
  | "critical"
  | "cross-protocol"
  | "credentials"
  | "poisoning"
  | "blast-radius"
  | "chokepoints";

export type DrawerTab =
  | "properties"
  | "connections"
  | "evidence"
  | "remediation";

export type BlastDirection = "out" | "in" | "both";

export interface HighlightState {
  nodeIds: string[];
  edgeIds: string[];
  title?: string;
}

interface ExplorerState {
  activeLens: LensId;
  subPresets: Record<LensId, string[]>;
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  hoveredNodeId: string | null;
  drawerOpen: boolean;
  drawerTab: DrawerTab;
  blastRadiusSourceId: string | null;
  blastRadiusDirection: BlastDirection;
  blastRadiusMaxHops: number;
  showOrphans: boolean;
  highlight: HighlightState | null;
  contextMenu: {
    nodeId: string;
    x: number;
    y: number;
  } | null;
}

interface ExplorerActions {
  setActiveLens: (lens: LensId) => void;
  setSubPresets: (lens: LensId, presets: string[]) => void;
  toggleSubPreset: (lens: LensId, preset: string) => void;
  selectNode: (id: string | null) => void;
  selectEdge: (id: string | null) => void;
  setHoveredNode: (id: string | null) => void;
  clearSelection: () => void;
  openDrawer: (tab?: DrawerTab) => void;
  closeDrawer: () => void;
  setDrawerTab: (tab: DrawerTab) => void;
  setBlastRadiusSource: (id: string | null) => void;
  setBlastRadiusDirection: (direction: BlastDirection) => void;
  setBlastRadiusMaxHops: (hops: number) => void;
  clearBlastRadius: () => void;
  toggleShowOrphans: () => void;
  setHighlight: (highlight: HighlightState | null) => void;
  clearHighlight: () => void;
  openContextMenu: (nodeId: string, x: number, y: number) => void;
  closeContextMenu: () => void;
}

const DEFAULT_SUB_PRESETS: Record<LensId, string[]> = {
  topology: [
    "TRUSTS_SERVER",
    "PROVIDES_TOOL",
    "PROVIDES_RESOURCE",
    "PROVIDES_PROMPT",
    "ADVERTISES_SKILL",
    "RUNS_ON",
    "CONFIGURED_IN",
    "LOADS_INSTRUCTIONS",
  ],
  "attack-surface": [
    "HAS_ACCESS_TO",
    "CAN_EXECUTE",
    "CAN_REACH",
    "CAN_EXFILTRATE_VIA",
  ],
  critical: [],
  "cross-protocol": [],
  credentials: ["AUTHENTICATES_WITH", "USES_CREDENTIAL", "HAS_ENV_VAR"],
  poisoning: ["SHADOWS", "POISONED_DESCRIPTION", "POISONED_INSTRUCTIONS"],
  "blast-radius": [],
  chokepoints: [],
};

export const useExplorerStore = create<ExplorerState & ExplorerActions>()(
  (set) => ({
    activeLens: "topology",
    subPresets: DEFAULT_SUB_PRESETS,
    selectedNodeId: null,
    selectedEdgeId: null,
    hoveredNodeId: null,
    drawerOpen: false,
    drawerTab: "properties",
    blastRadiusSourceId: null,
    blastRadiusDirection: "out",
    blastRadiusMaxHops: 6,
    showOrphans: false,
    highlight: null,
    contextMenu: null,

    setActiveLens: (lens) => set({ activeLens: lens, highlight: null, contextMenu: null }),

    setSubPresets: (lens, presets) =>
      set((state) => ({
        subPresets: { ...state.subPresets, [lens]: presets },
      })),

    toggleSubPreset: (lens, preset) =>
      set((state) => {
        const current = state.subPresets[lens] ?? [];
        const next = current.includes(preset)
          ? current.filter((p) => p !== preset)
          : [...current, preset];
        return {
          subPresets: { ...state.subPresets, [lens]: next },
        };
      }),

    selectNode: (id) => set({ selectedNodeId: id, selectedEdgeId: null }),

    selectEdge: (id) => set({ selectedEdgeId: id, selectedNodeId: null }),

    setHoveredNode: (id) => set({ hoveredNodeId: id }),

    clearSelection: () =>
      set({
        selectedNodeId: null,
        selectedEdgeId: null,
        drawerOpen: false,
        highlight: null,
        contextMenu: null,
      }),

    openDrawer: (tab) =>
      set((state) => ({
        drawerOpen: true,
        drawerTab: tab ?? state.drawerTab,
      })),

    closeDrawer: () => set({ drawerOpen: false }),

    setDrawerTab: (tab) => set({ drawerTab: tab }),

    setBlastRadiusSource: (id) => set({ blastRadiusSourceId: id }),

    setBlastRadiusDirection: (direction) =>
      set({ blastRadiusDirection: direction }),

    setBlastRadiusMaxHops: (hops) =>
      set({ blastRadiusMaxHops: Math.max(1, Math.min(10, hops)) }),

    clearBlastRadius: () => set({ blastRadiusSourceId: null }),

    toggleShowOrphans: () =>
      set((state) => ({ showOrphans: !state.showOrphans })),

    setHighlight: (highlight) => set({ highlight }),

    clearHighlight: () => set({ highlight: null }),

    openContextMenu: (nodeId, x, y) =>
      set({ contextMenu: { nodeId, x, y } }),

    closeContextMenu: () => set({ contextMenu: null }),
  }),
);

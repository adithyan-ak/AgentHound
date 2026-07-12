import { create } from "zustand";
import { persist } from "zustand/middleware";
import { LENS_LIST } from "./lens-config";
import type { LensEdgeData } from "./graph";

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
  | "remediation"
  | "findings";

export type BlastDirection = "out" | "in" | "both";

export interface HighlightState {
  nodeIds: string[];
  edgeIds: string[];
  title?: string;
}

/** A selected edge carries its full bundled data so the edge drawer can render
 * every constituent relationship without re-parsing the React-Flow edge id. */
export interface SelectedEdge {
  id: string;
  source: string;
  target: string;
  data: LensEdgeData;
}

/** Edge under the cursor — drives the floating edge tooltip. */
export interface HoveredEdge {
  id: string;
  source: string;
  target: string;
  data: LensEdgeData;
  x: number;
  y: number;
}

/** A request to pan/zoom the canvas onto a set of nodes (deep-link focus). */
export interface PendingFocus {
  nodeIds: string[];
  title?: string;
}

export interface ExplorerState {
  activeLens: LensId;
  subPresets: Record<LensId, string[]>;
  selectedNodeId: string | null;
  selectedEdge: SelectedEdge | null;
  hoveredEdge: HoveredEdge | null;
  pendingFocus: PendingFocus | null;
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
  selectEdge: (edge: SelectedEdge | null) => void;
  setHoveredEdge: (edge: HoveredEdge | null) => void;
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
  setPendingFocus: (focus: PendingFocus | null) => void;
  openContextMenu: (nodeId: string, x: number, y: number) => void;
  closeContextMenu: () => void;
}

// Default-enabled sub-presets are DERIVED from lens-config's `defaultEnabled`
// flags so the two can never drift. This was previously a hand-maintained
// literal that silently fell behind lens-config as new edge kinds were added,
// leaving genuinely-emitted edges (e.g. CAN_IMPERSONATE, EXPOSES_CREDENTIAL)
// off by default. `LensId` is imported by lens-config as a type-only import,
// so this value import introduces no runtime circular dependency.
export const DEFAULT_SUB_PRESETS = Object.fromEntries(
  LENS_LIST.map((lens) => [
    lens.id,
    lens.subPresets.filter((sp) => sp.defaultEnabled).map((sp) => sp.id),
  ]),
) as Record<LensId, string[]>;

export const useExplorerStore = create<ExplorerState & ExplorerActions>()(
  persist(
    (set) => ({
      activeLens: "topology",
      subPresets: DEFAULT_SUB_PRESETS,
      selectedNodeId: null,
      selectedEdge: null,
      hoveredEdge: null,
      pendingFocus: null,
      drawerOpen: false,
      drawerTab: "properties",
      blastRadiusSourceId: null,
      blastRadiusDirection: "out",
      blastRadiusMaxHops: 6,
      showOrphans: false,
      highlight: null,
      contextMenu: null,

      setActiveLens: (lens) =>
        set({ activeLens: lens, highlight: null, contextMenu: null }),

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

      selectNode: (id) =>
        set({ selectedNodeId: id, selectedEdge: null }),

      selectEdge: (edge) =>
        set({ selectedEdge: edge, selectedNodeId: null }),

      setHoveredEdge: (edge) => set({ hoveredEdge: edge }),

      clearSelection: () =>
        set({
          selectedNodeId: null,
          selectedEdge: null,
          hoveredEdge: null,
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

      setPendingFocus: (focus) => set({ pendingFocus: focus }),

      openContextMenu: (nodeId, x, y) =>
        set({ contextMenu: { nodeId, x, y } }),

      closeContextMenu: () => set({ contextMenu: null }),
    }),
    {
      // Persist only durable view preferences. Selection / hover / focus /
      // blast-radius are ephemeral and intentionally excluded so a reload
      // restores the user's lens + sub-preset choices without restoring a
      // stale selection.
      name: "agenthound-explorer-view",
      partialize: (state) => ({
        activeLens: state.activeLens,
        subPresets: state.subPresets,
      }),
    },
  ),
);

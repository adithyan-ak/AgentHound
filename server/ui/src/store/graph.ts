import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { NodeKind, EdgeKind } from "@/api/types";

export const ALL_NODE_KINDS: NodeKind[] = [
  "MCPServer",
  "MCPTool",
  "MCPResource",
  "MCPPrompt",
  "A2AAgent",
  "A2ASkill",
  "AgentInstance",
  "Identity",
  "Credential",
  "Host",
  "ConfigFile",
  "InstructionFile",
  "ResourceGroup",
  "TrustZone",
];

export const ALL_EDGE_KINDS: EdgeKind[] = [
  "TRUSTS_SERVER",
  "PROVIDES_TOOL",
  "PROVIDES_RESOURCE",
  "PROVIDES_PROMPT",
  "ADVERTISES_SKILL",
  "DELEGATES_TO",
  "AUTHENTICATES_WITH",
  "USES_CREDENTIAL",
  "RUNS_ON",
  "CONFIGURED_IN",
  "HAS_ENV_VAR",
  "LOADS_INSTRUCTIONS",
  "SAME_AUTH_DOMAIN",
  "HAS_ACCESS_TO",
  "CAN_EXECUTE",
  "SHADOWS",
  "POISONED_DESCRIPTION",
  "CAN_REACH",
  "CAN_EXFILTRATE_VIA",
  "CAN_IMPERSONATE",
  "POISONED_INSTRUCTIONS",
];

interface ActiveFilters {
  nodeKinds: Set<string>;
  edgeKinds: Set<string>;
  minRiskScore: number;
}

interface HighlightedPath {
  nodeIds: string[];
  edgeKeys: string[];
  title?: string;
}

interface GraphState {
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  hoveredNodeId: string | null;
  activeFilters: ActiveFilters;
  highlightedPath: HighlightedPath | null;
  ownedNodeIds: string[];
  highValueNodeIds: string[];
}

interface GraphActions {
  selectNode: (id: string | null) => void;
  selectEdge: (id: string | null) => void;
  hoverNode: (id: string) => void;
  clearHover: () => void;
  setFilters: (filters: Partial<ActiveFilters>) => void;
  toggleNodeKind: (kind: string) => void;
  toggleEdgeKind: (kind: string) => void;
  setNodeKinds: (kinds: string[]) => void;
  setMinRiskScore: (score: number) => void;
  highlightPath: (path: HighlightedPath) => void;
  clearHighlight: () => void;
  clearSelection: () => void;
  toggleOwned: (id: string) => void;
  toggleHighValue: (id: string) => void;
  isOwned: (id: string) => boolean;
  isHighValue: (id: string) => boolean;
}

type PersistedShape = {
  ownedNodeIds: string[];
  highValueNodeIds: string[];
};

export const useGraphStore = create<GraphState & GraphActions>()(
  persist(
    (set, get) => ({
      selectedNodeId: null,
      selectedEdgeId: null,
      hoveredNodeId: null,
      activeFilters: {
        nodeKinds: new Set<string>(ALL_NODE_KINDS),
        edgeKinds: new Set<string>([
          "TRUSTS_SERVER",
          "PROVIDES_TOOL",
          "PROVIDES_RESOURCE",
          "PROVIDES_PROMPT",
          "ADVERTISES_SKILL",
          "DELEGATES_TO",
          "SHADOWS",
          "POISONED_DESCRIPTION",
          "POISONED_INSTRUCTIONS",
          "CAN_REACH",
          "CAN_EXFILTRATE_VIA",
          "CAN_EXECUTE",
          "HAS_ACCESS_TO",
          "CAN_IMPERSONATE",
          "RUNS_ON",
        ]),
        minRiskScore: 0,
      },
      highlightedPath: null,
      ownedNodeIds: [],
      highValueNodeIds: [],

      selectNode: (id) => set({ selectedNodeId: id, selectedEdgeId: null }),

      selectEdge: (id) => set({ selectedEdgeId: id, selectedNodeId: null }),

      hoverNode: (id) => set({ hoveredNodeId: id }),

      clearHover: () => set({ hoveredNodeId: null }),

      setFilters: (filters) =>
        set((state) => ({
          activeFilters: { ...state.activeFilters, ...filters },
        })),

      toggleNodeKind: (kind) =>
        set((state) => {
          const next = new Set(state.activeFilters.nodeKinds);
          if (next.has(kind)) {
            next.delete(kind);
          } else {
            next.add(kind);
          }
          return { activeFilters: { ...state.activeFilters, nodeKinds: next } };
        }),

      toggleEdgeKind: (kind) =>
        set((state) => {
          const next = new Set(state.activeFilters.edgeKinds);
          if (next.has(kind)) {
            next.delete(kind);
          } else {
            next.add(kind);
          }
          return { activeFilters: { ...state.activeFilters, edgeKinds: next } };
        }),

      setNodeKinds: (kinds) =>
        set((state) => ({
          activeFilters: {
            ...state.activeFilters,
            nodeKinds: new Set<string>(kinds),
          },
        })),

      setMinRiskScore: (score) =>
        set((state) => ({
          activeFilters: { ...state.activeFilters, minRiskScore: score },
        })),

      highlightPath: (path) => set({ highlightedPath: path }),

      clearHighlight: () => set({ highlightedPath: null }),

      clearSelection: () =>
        set({
          selectedNodeId: null,
          selectedEdgeId: null,
          highlightedPath: null,
        }),

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

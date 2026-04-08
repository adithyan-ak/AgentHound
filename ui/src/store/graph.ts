import { create } from "zustand";
import type { NodeKind, EdgeKind } from "@/api/types";

const ALL_NODE_KINDS: NodeKind[] = [
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

const ALL_EDGE_KINDS: EdgeKind[] = [
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
}

interface GraphState {
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  activeFilters: ActiveFilters;
  highlightedPath: HighlightedPath | null;
}

interface GraphActions {
  selectNode: (id: string | null) => void;
  hoverNode: (id: string) => void;
  clearHover: () => void;
  setFilters: (filters: Partial<ActiveFilters>) => void;
  toggleNodeKind: (kind: string) => void;
  toggleEdgeKind: (kind: string) => void;
  setMinRiskScore: (score: number) => void;
  highlightPath: (path: HighlightedPath) => void;
  clearHighlight: () => void;
  clearSelection: () => void;
}

export const useGraphStore = create<GraphState & GraphActions>()((set) => ({
  selectedNodeId: null,
  hoveredNodeId: null,
  activeFilters: {
    nodeKinds: new Set<string>(ALL_NODE_KINDS),
    edgeKinds: new Set<string>(ALL_EDGE_KINDS),
    minRiskScore: 0,
  },
  highlightedPath: null,

  selectNode: (id) => set({ selectedNodeId: id }),

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

  setMinRiskScore: (score) =>
    set((state) => ({
      activeFilters: { ...state.activeFilters, minRiskScore: score },
    })),

  highlightPath: (path) => set({ highlightedPath: path }),

  clearHighlight: () => set({ highlightedPath: null }),

  clearSelection: () =>
    set({ selectedNodeId: null, highlightedPath: null }),
}));

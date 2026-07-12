import type { LucideIcon } from "lucide-react";
import {
  Network,
  Swords,
  AlertOctagon,
  GitBranchPlus,
  KeyRound,
  Biohazard,
  Radar,
  Waypoints,
} from "lucide-react";
import type { LensId } from "./store";
import { EDGE_KIND_META, type EdgeKind } from "@entities/graph/dto";
import { NODE_KIND_COLORS, LENS_ACCENT } from "@shared/theme/tokens";

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export interface SubPresetDefinition {
  id: string;
  label: string;
  description: string;
  defaultEnabled: boolean;
}

export interface LensDefinition {
  id: LensId;
  label: string;
  shortLabel: string;
  icon: LucideIcon;
  activeTint: string; // hex color used for the active pill background glow
  accentClass: string; // tailwind class for the pill when active
  description: string;
  /**
   * Edge kinds this lens displays. Empty array means "special lens"
   * (Critical, Cross-Protocol, Blast Radius, Chokepoints) whose edge
   * selection is driven by findings or runtime state.
   */
  edgeKinds: string[];
  /**
   * If true, nodes and edges that are not in the lens scope are
   * rendered at very low opacity rather than hidden entirely.
   */
  dimOthers: boolean;
  subPresets: SubPresetDefinition[];
  /**
   * Whether node severity halos are applied under this lens.
   */
  showSeverityHalos: boolean;
  /**
   * Whether edges carry severity coloring under this lens.
   */
  colorEdgesBySeverity: boolean;
}

export const LENS_LIST: LensDefinition[] = [
  {
    id: "topology",
    label: "Topology",
    shortLabel: "Topology",
    icon: Network,
    activeTint: LENS_ACCENT.topology,
    accentClass: "bg-blue-500 text-white",
    description:
      "What exists and what trusts what. Raw structural edges only, no severity coloring.",
    edgeKinds: [
      "TRUSTS_SERVER",
      "PROVIDES_TOOL",
      "PROVIDES_RESOURCE",
      "PROVIDES_PROMPT",
      "ADVERTISES_SKILL",
      "DELEGATES_TO",
      "RUNS_ON",
      "CONFIGURED_IN",
      "LOADS_INSTRUCTIONS",
      "SAME_AUTH_DOMAIN",
      "EXPOSES",
      "PROVIDES_MODEL",
      "EXTRACTED_FROM",
    ],
    dimOthers: false,
    subPresets: [
      {
        id: "TRUSTS_SERVER",
        label: "Trusts server",
        description: "Agent → MCP server trust",
        defaultEnabled: true,
      },
      {
        id: "PROVIDES_TOOL",
        label: "Provides tool",
        description: "Server → tool",
        defaultEnabled: true,
      },
      {
        id: "PROVIDES_RESOURCE",
        label: "Provides resource",
        description: "Server → resource",
        defaultEnabled: true,
      },
      {
        id: "PROVIDES_PROMPT",
        label: "Provides prompt",
        description: "Server → prompt template",
        defaultEnabled: true,
      },
      {
        id: "ADVERTISES_SKILL",
        label: "Advertises skill",
        description: "A2A agent → skill",
        defaultEnabled: true,
      },
      {
        id: "DELEGATES_TO",
        label: "Delegates to",
        description: "A2A agent → A2A agent delegation",
        defaultEnabled: true,
      },
      {
        id: "RUNS_ON",
        label: "Runs on",
        description: "Server/agent → host",
        defaultEnabled: true,
      },
      {
        id: "CONFIGURED_IN",
        label: "Configured in",
        description: "Server → config file",
        defaultEnabled: true,
      },
      {
        id: "LOADS_INSTRUCTIONS",
        label: "Loads instructions",
        description: "Client → instruction file",
        defaultEnabled: true,
      },
      {
        id: "SAME_AUTH_DOMAIN",
        label: "Same auth domain",
        description: "A2A agents share auth domain",
        defaultEnabled: true,
      },
      {
        id: "EXPOSES",
        label: "Exposes",
        description: "AI service → AI service dependency",
        defaultEnabled: true,
      },
      {
        id: "PROVIDES_MODEL",
        label: "Provides model",
        description: "AI service → model artifact",
        defaultEnabled: true,
      },
      {
        id: "EXTRACTED_FROM",
        label: "Extracted from",
        description: "Model → extracted training signal",
        defaultEnabled: true,
      },
    ],
    showSeverityHalos: false,
    colorEdgesBySeverity: false,
  },
  {
    id: "attack-surface",
    label: "Attack Surface",
    shortLabel: "Attack",
    icon: Swords,
    activeTint: LENS_ACCENT.attack,
    accentClass: "bg-orange-500 text-white",
    description:
      "What can do what. Composite edges showing inferred reach, execution, and exfiltration.",
    edgeKinds: [
      "HAS_ACCESS_TO",
      "CAN_EXECUTE",
      "CAN_REACH",
      "CAN_REACH_CROSS_PROTOCOL",
      "CAN_EXFILTRATE_VIA",
      "CAN_IMPERSONATE",
      "CONFUSED_DEPUTY",
    ],
    dimOthers: false,
    subPresets: [
      {
        id: "HAS_ACCESS_TO",
        label: "Has Access To",
        description: "Tool → resource capability match",
        defaultEnabled: true,
      },
      {
        id: "CAN_EXECUTE",
        label: "Can Execute",
        description: "Tool → host code execution",
        defaultEnabled: true,
      },
      {
        id: "CAN_REACH",
        label: "Can Reach",
        description: "Agent → resource transitive reach",
        defaultEnabled: true,
      },
      {
        id: "CAN_REACH_CROSS_PROTOCOL",
        label: "Reach (X-Proto)",
        description: "Agent → resource across A2A/MCP protocols",
        defaultEnabled: true,
      },
      {
        id: "CAN_EXFILTRATE_VIA",
        label: "Can Exfiltrate",
        description: "Agent → outbound channel composite",
        defaultEnabled: true,
      },
      {
        id: "CAN_IMPERSONATE",
        label: "Can Impersonate",
        description: "A2A agent → similar A2A agent",
        defaultEnabled: true,
      },
      {
        id: "CONFUSED_DEPUTY",
        label: "Confused Deputy",
        description: "A2A agent → agent confused-deputy delegation",
        defaultEnabled: true,
      },
    ],
    showSeverityHalos: true,
    colorEdgesBySeverity: true,
  },
  {
    id: "critical",
    label: "Critical",
    shortLabel: "Critical",
    icon: AlertOctagon,
    activeTint: LENS_ACCENT.critical,
    accentClass: "bg-red-600 text-white",
    description:
      "Only edges that participate in critical-severity findings. Everything else dimmed.",
    edgeKinds: [],
    dimOthers: true,
    subPresets: [],
    showSeverityHalos: true,
    colorEdgesBySeverity: true,
  },
  {
    id: "cross-protocol",
    label: "Cross-Protocol",
    shortLabel: "Cross",
    icon: GitBranchPlus,
    activeTint: NODE_KIND_COLORS.A2AAgent,
    accentClass: "bg-purple-500 text-white",
    description:
      "Only paths that cross the A2A ↔ MCP protocol boundary. The differentiator view.",
    edgeKinds: [],
    dimOthers: true,
    subPresets: [],
    showSeverityHalos: true,
    colorEdgesBySeverity: true,
  },
  {
    id: "credentials",
    label: "Credentials",
    shortLabel: "Creds",
    icon: KeyRound,
    activeTint: NODE_KIND_COLORS.Credential,
    accentClass: "bg-pink-500 text-white",
    description:
      "Identity and credential flow. Highlights exposed secrets and high-entropy values.",
    edgeKinds: [
      "AUTHENTICATES_WITH",
      "USES_CREDENTIAL",
      "HAS_ENV_VAR",
      "EXPOSES_CREDENTIAL",
      "CAN_REACH_CREDENTIAL_CHAIN",
    ],
    dimOthers: false,
    subPresets: [
      {
        id: "AUTHENTICATES_WITH",
        label: "Authenticates with",
        description: "Server/agent → identity",
        defaultEnabled: true,
      },
      {
        id: "USES_CREDENTIAL",
        label: "Uses credential",
        description: "Identity → credential",
        defaultEnabled: true,
      },
      {
        id: "HAS_ENV_VAR",
        label: "Has env var",
        description: "Server → credential env",
        defaultEnabled: true,
      },
      {
        id: "EXPOSES_CREDENTIAL",
        label: "Exposes credential",
        description: "AI service → credential material",
        defaultEnabled: true,
      },
      {
        id: "CAN_REACH_CREDENTIAL_CHAIN",
        label: "Credential chain",
        description: "Agent → upstream credential reach",
        defaultEnabled: true,
      },
    ],
    showSeverityHalos: true,
    colorEdgesBySeverity: false,
  },
  {
    id: "poisoning",
    label: "Poisoning",
    shortLabel: "Poison",
    icon: Biohazard,
    activeTint: NODE_KIND_COLORS.InstructionFile,
    accentClass: "bg-yellow-500 text-slate-900",
    description:
      "Prompt-injection patterns in tool descriptions, shadowing, and instruction-file attacks.",
    edgeKinds: [
      "SHADOWS",
      "POISONED_DESCRIPTION",
      "POISONED_INSTRUCTIONS",
      "INGESTS_UNTRUSTED",
      "TAINTS",
      "IFC_VIOLATION",
      "POISONS_CONTEXT",
    ],
    dimOthers: false,
    subPresets: [
      {
        id: "POISONED_DESCRIPTION",
        label: "Poisoned description",
        description: "Tool has injection patterns",
        defaultEnabled: true,
      },
      {
        id: "SHADOWS",
        label: "Tool shadowing",
        description: "Tool references another tool by name",
        defaultEnabled: true,
      },
      {
        id: "POISONED_INSTRUCTIONS",
        label: "Poisoned instructions",
        description: "CLAUDE.md / .cursorrules imperative overrides",
        defaultEnabled: true,
      },
      {
        id: "INGESTS_UNTRUSTED",
        label: "Ingests untrusted",
        description: "Tool → resource untrusted-content ingestion",
        defaultEnabled: true,
      },
      {
        id: "TAINTS",
        label: "Taints",
        description: "Tool → downstream tool taint propagation",
        defaultEnabled: true,
      },
      {
        id: "IFC_VIOLATION",
        label: "IFC violation",
        description: "Information-flow-control violation between tools",
        defaultEnabled: true,
      },
      {
        id: "POISONS_CONTEXT",
        label: "Poisons context",
        description: "Tool → agent context poisoning",
        defaultEnabled: true,
      },
    ],
    showSeverityHalos: true,
    colorEdgesBySeverity: true,
  },
  {
    id: "blast-radius",
    label: "Blast Radius",
    shortLabel: "Blast",
    icon: Radar,
    activeTint: NODE_KIND_COLORS.MCPServer,
    accentClass: "bg-emerald-500 text-white",
    description:
      "Pick a node. See everything reachable from it, grouped by hop distance.",
    edgeKinds: [],
    dimOthers: true,
    subPresets: [],
    showSeverityHalos: true,
    colorEdgesBySeverity: false,
  },
  {
    id: "chokepoints",
    label: "Chokepoints",
    shortLabel: "Choke",
    icon: Waypoints,
    activeTint: NODE_KIND_COLORS.AgentInstance,
    accentClass: "bg-cyan-500 text-white",
    description:
      "Nodes ranked by combined in/out degree. Single points of failure sized proportionally.",
    edgeKinds: [],
    dimOthers: false,
    subPresets: [],
    showSeverityHalos: false,
    colorEdgesBySeverity: false,
  },
];

export const LENS_MAP: Record<LensId, LensDefinition> = LENS_LIST.reduce(
  (acc, lens) => {
    acc[lens.id] = lens;
    return acc;
  },
  {} as Record<LensId, LensDefinition>,
);

export function getLens(id: LensId): LensDefinition {
  return LENS_MAP[id];
}

/**
 * Maps a finding's headline edge kind to the lens that best frames it, so a
 * "View in Explorer" deep-link lands on the right view rather than the default
 * topology. Derived from the generated EDGE_KIND_META lens category (the Go
 * source of truth) so every one of the 32 edge kinds — including new ones —
 * routes to the correct lens automatically instead of drifting against a
 * hand-maintained switch. The four lens categories map 1:1 to explorer lens
 * ids; anything unrecognized falls back to Topology.
 */
export function lensForEdgeKind(kind: string): LensId {
  const meta = EDGE_KIND_META[kind as EdgeKind];
  switch (meta?.lens) {
    case "credentials":
      return "credentials";
    case "poisoning":
      return "poisoning";
    case "attack-surface":
      return "attack-surface";
    case "topology":
      return "topology";
    default:
      return "topology";
  }
}

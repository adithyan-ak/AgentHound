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
import type { LensId } from "@/store/explorer";

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
    activeTint: "#3B82F6",
    accentClass: "bg-blue-500 text-white",
    description:
      "What exists and what trusts what. Raw structural edges only, no severity coloring.",
    edgeKinds: [
      "TRUSTS_SERVER",
      "PROVIDES_TOOL",
      "PROVIDES_RESOURCE",
      "PROVIDES_PROMPT",
      "ADVERTISES_SKILL",
      "RUNS_ON",
      "CONFIGURED_IN",
      "LOADS_INSTRUCTIONS",
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
    ],
    showSeverityHalos: false,
    colorEdgesBySeverity: false,
  },
  {
    id: "attack-surface",
    label: "Attack Surface",
    shortLabel: "Attack",
    icon: Swords,
    activeTint: "#F97316",
    accentClass: "bg-orange-500 text-white",
    description:
      "What can do what. Composite edges showing inferred reach, execution, and exfiltration.",
    edgeKinds: ["HAS_ACCESS_TO", "CAN_EXECUTE", "CAN_REACH", "CAN_EXFILTRATE_VIA"],
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
        id: "CAN_EXFILTRATE_VIA",
        label: "Can Exfiltrate",
        description: "Agent → outbound channel composite",
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
    activeTint: "#DC2626",
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
    activeTint: "#A855F7",
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
    activeTint: "#EC4899",
    accentClass: "bg-pink-500 text-white",
    description:
      "Identity and credential flow. Highlights exposed secrets and high-entropy values.",
    edgeKinds: ["AUTHENTICATES_WITH", "USES_CREDENTIAL", "HAS_ENV_VAR"],
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
    ],
    showSeverityHalos: true,
    colorEdgesBySeverity: false,
  },
  {
    id: "poisoning",
    label: "Poisoning",
    shortLabel: "Poison",
    icon: Biohazard,
    activeTint: "#EAB308",
    accentClass: "bg-yellow-500 text-slate-900",
    description:
      "Prompt-injection patterns in tool descriptions, shadowing, and instruction-file attacks.",
    edgeKinds: ["SHADOWS", "POISONED_DESCRIPTION", "POISONED_INSTRUCTIONS"],
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
    ],
    showSeverityHalos: true,
    colorEdgesBySeverity: true,
  },
  {
    id: "blast-radius",
    label: "Blast Radius",
    shortLabel: "Blast",
    icon: Radar,
    activeTint: "#10B981",
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
    activeTint: "#06B6D4",
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

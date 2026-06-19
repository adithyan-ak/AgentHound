import { AlertOctagon, AlertTriangle, AlertCircle, Info } from "lucide-react";
import type { LucideIcon } from "lucide-react";

// Canonical node kind colors — matches hex-config palette.
// Typed as a const-asserted object so consumers get string (not
// string | undefined) on indexed access without a fallback hex.
// Supplemental indexable type at the bottom of the file.
export const NODE_KIND_COLORS = {
  AgentInstance: "#06B6D4",    // cyan-500
  A2AAgent: "#A855F7",        // purple-500
  MCPServer: "#10B981",       // emerald-500
  MCPTool: "#F59E0B",         // amber-500
  MCPResource: "#EF4444",     // red-500
  MCPPrompt: "#FB923C",       // orange-400
  A2ASkill: "#C084FC",        // purple-400
  Host: "#475569",            // slate-600
  Identity: "#94A3B8",        // slate-400
  Credential: "#EC4899",      // pink-500
  ConfigFile: "#D97706",      // amber-600
  InstructionFile: "#EAB308", // yellow-500
  ResourceGroup: "#64748B",   // slate-500
  TrustZone: "#22D3EE",       // cyan-400
  // AI service kinds. Per-kind label is the dispatch key (per
  // node-styles.ts kinds[0] semantics); the umbrella :AIService stays
  // on the node as a multi-label companion so unified queries can match
  // (s:AIService) without enumerating per-kind labels. Every per-service
  // color is checked against the v0.1 palette above for visual distinctness
  // — the umbrella :AIService color is the fallback only when the
  // per-kind dispatch returns nothing.
  OllamaInstance: "#FF7043",     // orange-red — distinct from MCPTool amber
  LiteLLMGateway: "#EC407A",     // pink — sibling of Credential pink (the gateway IS the credential exposure)
  AIService: "#7E57C2",          // muted purple — generic umbrella fallback
  VLLMInstance: "#26A69A",       // teal — vLLM's "rocket" identity
  QdrantInstance: "#5C6BC0",     // indigo — vector-search identity, distinct from AgentInstance cyan
  MLflowServer: "#42A5F5",       // blue — MLflow brand-aligned blue
  JupyterServer: "#F57C00",      // deep orange — distinct from MCPPrompt #FB923C (orange-400)
  LangServeApp: "#9CCC65",       // chartreuse — distinct from AIService purple AND OpenWebUI green
  OpenWebUIInstance: "#66BB6A",  // green — chat-UI identity
  // v0.3 model-artifact node — emitted by the Ollama Looter (one per /api/tags
  // entry, properties from /api/show). Deep purple chosen because it sits next
  // to AIService #7E57C2 and A2AAgent #A855F7 in hue but is materially darker,
  // so the explorer renders model artifacts as the "weight" beneath their AI
  // service. Plan suggested #F44336 red but it collides with MCPResource
  // #EF4444 — readers can't distinguish a sensitive resource from a model.
  AIModel: "#6A1B9A",            // deep purple — distinct from A2AAgent / AIService / QdrantInstance
} as const satisfies Record<string, string>;

export type NodeKind = keyof typeof NODE_KIND_COLORS;

// Dynamic-key lookup alias: when callers receive a runtime kind string
// (e.g. from API responses), index through this view. Returns `string |
// undefined` — fall back to NODE_KIND_COLORS.Identity for unknown kinds.
export const NODE_KIND_COLORS_BY_KEY: Record<string, string | undefined> =
  NODE_KIND_COLORS;

// Severity system — solid color, muted bg, text, border, icon
export interface SeverityStyle {
  solid: string;
  bg: string;
  text: string;
  border: string;
  icon: LucideIcon;
  label: string;
  /** Tailwind classes for badge: bg + text + border */
  badgeClass: string;
  /** Tailwind class for left-border accent */
  borderLeftClass: string;
  /** Tailwind class for solid dot/indicator */
  dotClass: string;
}

export const SEVERITY = {
  critical: {
    solid: "#EF4444",
    bg: "rgba(239,68,68,0.12)",
    text: "#F87171",
    border: "rgba(239,68,68,0.30)",
    icon: AlertOctagon,
    label: "Critical",
    badgeClass: "bg-red-500/10 text-red-400 border-red-500/30",
    borderLeftClass: "border-l-red-500",
    dotClass: "bg-red-500",
  },
  high: {
    solid: "#F97316",
    bg: "rgba(249,115,22,0.12)",
    text: "#FB923C",
    border: "rgba(249,115,22,0.30)",
    icon: AlertTriangle,
    label: "High",
    badgeClass: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    borderLeftClass: "border-l-orange-500",
    dotClass: "bg-orange-500",
  },
  medium: {
    solid: "#EAB308",
    bg: "rgba(234,179,8,0.12)",
    text: "#FACC15",
    border: "rgba(234,179,8,0.30)",
    icon: AlertCircle,
    label: "Medium",
    badgeClass: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    borderLeftClass: "border-l-yellow-500",
    dotClass: "bg-yellow-500",
  },
  low: {
    solid: "#64748B",
    bg: "rgba(100,120,143,0.12)",
    text: "#94A3B8",
    border: "rgba(100,120,143,0.20)",
    icon: Info,
    label: "Low",
    badgeClass: "bg-slate-500/10 text-slate-400 border-slate-500/30",
    borderLeftClass: "border-l-slate-500",
    dotClass: "bg-slate-500",
  },
  info: {
    solid: "#3B82F6",
    bg: "rgba(59,130,246,0.12)",
    text: "#60A5FA",
    border: "rgba(59,130,246,0.30)",
    icon: Info,
    label: "Info",
    badgeClass: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    borderLeftClass: "border-l-blue-500",
    dotClass: "bg-blue-500",
  },
} as const satisfies Record<string, SeverityStyle>;

export type SeverityKey = keyof typeof SEVERITY;

// Dynamic-key lookup alias: when callers index by a runtime severity
// string, route through this view. Returns SeverityStyle | undefined —
// fall back to SEVERITY.low for unknown levels.
export const SEVERITY_BY_KEY: Record<string, SeverityStyle | undefined> =
  SEVERITY;

// Feedback colors for form validation / system messages
export const FEEDBACK = {
  success: { solid: "#22C55E", bg: "rgba(34,197,94,0.12)", text: "#4ADE80", border: "rgba(34,197,94,0.30)" },
  warning: { solid: "#F59E0B", bg: "rgba(245,158,11,0.12)", text: "#FBBF24", border: "rgba(245,158,11,0.30)" },
  error: { solid: "#EF4444", bg: "rgba(239,68,68,0.12)", text: "#F87171", border: "rgba(239,68,68,0.30)" },
  info: { solid: "#3B82F6", bg: "rgba(59,130,246,0.12)", text: "#60A5FA", border: "rgba(59,130,246,0.30)" },
} as const;

// ----------------------------------------------------------------------
// OBSIDIAN TERMINAL — signature accents.
// ONE primary accent (amber "terminal phosphor") + ONE functional OK
// signal (cool green). Everything else stays monochrome carbon. These are
// the only non-severity hues allowed on the dashboard chrome.
// ----------------------------------------------------------------------
export const ACCENT = "#F5A623"; // amber phosphor — primary highlight / hero metric
export const ACCENT_BRIGHT = "#FFB020"; // hotter amber — focus / leading edge
export const ACCENT_DIM = "#7A5A1E"; // amber, recessed — unfilled instrument ticks
export const SIGNAL_OK = "#3FB950"; // operational / OK only
export const TRIAGE_NEUTRAL = "#8B92A5"; // slate-gray — untouched "new" triage status

// Recharts theme constants — carbon panel surfaces, amber-led series.
export const CHART_THEME = {
  tooltip: {
    bg: "#121316",
    border: "#2A2D33",
    text: "#E9ECF0",
  },
  grid: "rgba(255,255,255,0.045)",
  axis: "#7A828E",
  series: ["#F5A623", "#6E7B91", "#3FB950", "#E5484D", "#C79A3A", "#5C9EAD", "#A8B0BD", "#FFB020"],
} as const;

// Risk score -> color utility. Bands keep their severity semantics; only the
// "clear" band adopts the theme's operational green.
export function riskColor(score: number): string {
  if (score >= 75) return "#EF4444";
  if (score >= 50) return "#F97316";
  if (score >= 25) return "#EAB308";
  return SIGNAL_OK;
}

// Canonical severity ordering (worst first) for dashboards and legends.
export const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

// Severity key -> solid color, falling back to the "low" slate.
export function severityColor(sev: string): string {
  return SEVERITY_BY_KEY[sev]?.solid ?? SEVERITY.low.solid;
}

// Risk score -> Tailwind bg class
export function riskBgClass(score: number): string {
  if (score >= 75) return "bg-red-500";
  if (score >= 50) return "bg-orange-500";
  if (score >= 25) return "bg-yellow-500";
  return "bg-green-500";
}

// Risk score -> Tailwind text class
export function riskTextClass(score: number): string {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-amber-400";
  return "text-green-400";
}

// Edge category colors
export const EDGE_COLORS = {
  attack: "#EF4444",
  trust: "#4A90D9",
  structure: "#475569",
} as const;

// Explorer hex-node fill
export const EXPLORER_HEX_FILL = "#0B1220";

// Lens accent tints — three accent tints for lenses whose semantics don't
// map onto NODE_KIND_COLORS. Defined here so the literal lives in one place
// and any color audit (Step 1 / linter) is single-source-of-truth.
export const LENS_ACCENT = {
  topology: "#3B82F6",   // blue-500 — neutral structural lens
  attack: "#F97316",     // orange-500 — generic attack-surface accent
  critical: "#DC2626",   // red-600 — distinct from MCPResource red-500 to
                         // separate "critical lens" chrome from "resource node" fill
} as const;

// Dimmed state palette — used by lenses that fade out-of-scope nodes/edges
// against the explorer canvas. These sit BETWEEN the canvas (#050B18) and
// Host/ResourceGroup (#475569 / #64748B), so dimmed elements visibly recede
// without disappearing into the background.
export const DIMMED = {
  deep: "#1E293B",   // slate-800 — "out of scope" / deepest dim
  mid: "#334155",    // slate-700 — "low centrality" / mid dim
} as const;

// ----------------------------------------------------------------------
// INSTRUMENT — support palette for hand-drawn SVG widgets (the RadialGauge,
// the cross-protocol MiniSankey, the AuthCoverage pie, inventory/chokepoint
// bars). These hues previously lived as inline hex inside those components;
// they are re-homed here so tokens.ts stays the sole TS hex source. Values
// are unchanged from their prior inline use — purely a relocation.
// ----------------------------------------------------------------------
export const INSTRUMENT = {
  canvas: "#0A0A0B",        // near-black app canvas backdrop (matches --mauve-1)
  panel: "#16171B",         // raised carbon node panel (sankey rects)
  grayMuted: "#6E7B91",     // neutral chart lane / bearer-auth slice
  grayDim: "#5C636E",       // dim gauge scale labels + sankey host stroke
  teal: "#5C9EAD",          // mTLS auth slice / secondary lane
  sankeyAgent: "#c4b5fd",   // A2A lane label tint (purple-300)
  sankeyHost: "#cbd5e1",    // host lane label tint (slate-300)
  sankeyResource: "#fca5a5", // MCP-resource lane label tint (red-300)
} as const;

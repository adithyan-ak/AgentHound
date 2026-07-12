import { useExplorerStore } from "@features/explorer/model/store";
import { getLens } from "@features/explorer/model/lens-config";
import { cn } from "@shared/lib/utils";
import { NODE_KIND_COLORS, NEUTRAL_NODE_COLOR, SEVERITY, DIMMED } from "@shared/theme/tokens";
import { getEdgeColor, edgeLabel, edgeDescription } from "@entities/edge";

interface NodeKeyItem {
  color: string;
  label: string;
}

// Node color key per lens — kept compact (nodes are already labeled on the
// canvas; this is a reference, not the primary reading aid).
const NODE_KEY_BY_LENS: Record<string, NodeKeyItem[]> = {
  topology: [
    { color: NODE_KIND_COLORS.AgentInstance, label: "Agent" },
    { color: NODE_KIND_COLORS.MCPServer, label: "MCP Server" },
    { color: NODE_KIND_COLORS.MCPTool, label: "Tool" },
    { color: NODE_KIND_COLORS.MCPResource, label: "Resource" },
  ],
  "attack-surface": [
    { color: NODE_KIND_COLORS.AgentInstance, label: "Agent" },
    { color: NODE_KIND_COLORS.MCPTool, label: "Tool" },
    { color: NODE_KIND_COLORS.MCPResource, label: "Resource" },
    { color: NODE_KIND_COLORS.Host, label: "Host" },
  ],
  critical: [
    { color: NODE_KIND_COLORS.AgentInstance, label: "Agent" },
    { color: NODE_KIND_COLORS.MCPTool, label: "Tool" },
    { color: NODE_KIND_COLORS.MCPResource, label: "Resource" },
  ],
  "cross-protocol": [
    { color: NODE_KIND_COLORS.A2AAgent, label: "A2A Agent" },
    { color: NODE_KIND_COLORS.MCPServer, label: "MCP Server" },
    { color: NODE_KIND_COLORS.MCPResource, label: "Resource" },
  ],
  credentials: [
    { color: NODE_KIND_COLORS.Credential, label: "Credential" },
    { color: NODE_KIND_COLORS.Identity, label: "Identity" },
    { color: NODE_KIND_COLORS.MCPServer, label: "MCP Server" },
  ],
  poisoning: [
    { color: NODE_KIND_COLORS.MCPTool, label: "Tool" },
    { color: NODE_KIND_COLORS.InstructionFile, label: "Instruction file" },
    { color: NODE_KIND_COLORS.AgentInstance, label: "Agent" },
  ],
  "blast-radius": [
    { color: NODE_KIND_COLORS.MCPServer, label: "Source node" },
    { color: NODE_KIND_COLORS.Identity, label: "Reachable" },
    { color: DIMMED.deep, label: "Out of scope" },
  ],
  chokepoints: [
    { color: NODE_KIND_COLORS.AgentInstance, label: "High centrality" },
    { color: NEUTRAL_NODE_COLOR, label: "Medium" },
    { color: DIMMED.mid, label: "Low" },
  ],
};

// Special lenses without sub-presets get a one-line edge explanation.
const SPECIAL_EDGE_NOTE: Record<string, string> = {
  critical: "Only edges in critical findings — colored by severity.",
  "blast-radius": "Edges reachable from the source node.",
  chokepoints: "All structural edges (degree sizes the nodes).",
};

const MAX_EDGE_ROWS = 7;

function LineSwatch({ color, dashed }: { color: string; dashed?: boolean }) {
  return (
    <svg width="22" height="8" className="flex-shrink-0">
      <line
        x1="0"
        y1="4"
        x2="22"
        y2="4"
        stroke={color}
        strokeWidth={2.25}
        strokeDasharray={dashed ? "4 3" : undefined}
      />
    </svg>
  );
}

export function Legend() {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const enabledPresets = useExplorerStore((s) => s.subPresets[activeLens] ?? []);
  const lens = getLens(activeLens);

  const hasSub = lens.subPresets.length > 0;
  // Reflect what's actually visible: enabled sub-presets, else the lens default.
  const edgeKinds = hasSub
    ? enabledPresets.length > 0
      ? enabledPresets
      : lens.edgeKinds
    : lens.edgeKinds;

  const nodeItems = NODE_KEY_BY_LENS[activeLens] ?? [];
  const severityColored = lens.colorEdgesBySeverity;
  const note = SPECIAL_EDGE_NOTE[activeLens];

  const shownEdges = edgeKinds.slice(0, MAX_EDGE_ROWS);
  const overflow = edgeKinds.length - shownEdges.length;

  return (
    <div
      className={cn(
        "pointer-events-auto absolute bottom-9 left-4 z-20 max-h-[60vh] w-[208px] overflow-y-auto rounded-md",
        "border border-border bg-card/95 px-3 py-2.5 backdrop-blur-md elev-2",
      )}
    >
      <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.05]" />
      <span
        aria-hidden
        className="pointer-events-none absolute left-0 top-0 h-px w-10"
        style={{ background: lens.activeTint, opacity: 0.9 }}
      />

      {/* EDGES — the relationship decoder */}
      <div className="mb-1.5 font-mono text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {lens.shortLabel} edges
      </div>

      {severityColored && (
        <div className="mb-2 space-y-1">
          <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-muted-foreground/70">
            line color = severity
          </div>
          {(
            [
              ["critical", SEVERITY.critical.solid],
              ["high", SEVERITY.high.solid],
              ["medium", SEVERITY.medium.solid],
            ] as const
          ).map(([label, color]) => (
            <div key={label} className="flex items-center gap-2">
              <LineSwatch color={color} />
              <span className="font-mono text-[10px] capitalize text-foreground/80">{label}</span>
            </div>
          ))}
          <div className="flex items-center gap-2">
            <LineSwatch color={NODE_KIND_COLORS.A2AAgent} dashed />
            <span className="font-mono text-[10px] text-foreground/80">cross-protocol</span>
          </div>
        </div>
      )}

      {note && (
        <p className="mb-2 text-[10px] leading-snug text-muted-foreground">{note}</p>
      )}

      {!severityColored && shownEdges.length > 0 && (
        <div className="mb-2 space-y-1">
          {shownEdges.map((kind) => (
            <div key={kind} className="flex items-center gap-2" title={edgeDescription(kind)}>
              <LineSwatch color={getEdgeColor(kind)} />
              <span className="truncate font-mono text-[10px] text-foreground/80">
                {edgeLabel(kind).toLowerCase()}
              </span>
            </div>
          ))}
          {overflow > 0 && (
            <div className="font-mono text-[9px] text-muted-foreground/70">+{overflow} more</div>
          )}
        </div>
      )}

      {/* When severity-colored, still list which relationships are in scope. */}
      {severityColored && shownEdges.length > 0 && (
        <div className="mb-2 flex flex-wrap gap-1">
          {shownEdges.map((kind) => (
            <span
              key={kind}
              title={edgeDescription(kind)}
              className="rounded-[2px] border border-border bg-black/30 px-1 py-0.5 font-mono text-[8px] uppercase tracking-[0.04em] text-muted-foreground"
            >
              {edgeLabel(kind)}
            </span>
          ))}
          {overflow > 0 && (
            <span className="font-mono text-[8px] text-muted-foreground/70">+{overflow}</span>
          )}
        </div>
      )}

      {/* NODES — compact color key */}
      {nodeItems.length > 0 && (
        <>
          <div className="mb-1.5 mt-2 border-t border-border/60 pt-2 font-mono text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            nodes
          </div>
          <div className="space-y-1">
            {nodeItems.map((item) => (
              <div key={item.label} className="flex items-center gap-2">
                <span className="h-2 w-2 flex-shrink-0 rounded-[1px]" style={{ background: item.color }} />
                <span className="font-mono text-[10px] text-foreground/80">{item.label}</span>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="mt-2 border-t border-border/60 pt-1.5 font-mono text-[8px] uppercase tracking-[0.1em] text-muted-foreground/70">
        hover a line to read · click to inspect
      </div>
    </div>
  );
}

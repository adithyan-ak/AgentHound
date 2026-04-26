import { useEffect, useMemo, useRef } from "react";
import {
  Crosshair,
  ArrowDown,
  ArrowUp,
  Radar,
  FileLock2,
  Shield,
  Target,
  Crown,
  Copy,
  FileText,
  Focus,
  type LucideIcon,
} from "lucide-react";
import { useExplorerStore } from "@/store/explorer";
import { useGraphStore } from "@/store/graph";
import { useExplorerGraph } from "@/hooks/useExplorerGraph";
import { getHexConfig } from "@/lib/explorer/hex-config";
import type { APIEdge } from "@/api/types";
import { cn } from "@/lib/utils";

const MENU_WIDTH = 260;
const MENU_HEIGHT_ESTIMATE = 520;

interface MenuItem {
  type: "item";
  icon: LucideIcon;
  label: string;
  shortcut?: string;
  onSelect: () => void;
  destructive?: boolean;
  active?: boolean;
  disabled?: boolean;
}

interface MenuDivider {
  type: "divider";
}

interface MenuSection {
  type: "section";
  label: string;
}

type MenuEntry = MenuItem | MenuDivider | MenuSection;

export function ExplorerNodeContextMenu() {
  const contextMenu = useExplorerStore((s) => s.contextMenu);
  const closeContextMenu = useExplorerStore((s) => s.closeContextMenu);
  const activeLens = useExplorerStore((s) => s.activeLens);
  const blastSourceId = useExplorerStore((s) => s.blastRadiusSourceId);
  const setActiveLens = useExplorerStore((s) => s.setActiveLens);
  const setBlastRadiusSource = useExplorerStore((s) => s.setBlastRadiusSource);
  const selectNode = useExplorerStore((s) => s.selectNode);
  const openDrawer = useExplorerStore((s) => s.openDrawer);
  const setHighlight = useExplorerStore((s) => s.setHighlight);

  const toggleOwned = useGraphStore((s) => s.toggleOwned);
  const toggleHighValue = useGraphStore((s) => s.toggleHighValue);
  const isOwned = useGraphStore((s) => s.isOwned);
  const isHighValue = useGraphStore((s) => s.isHighValue);

  const { data } = useExplorerGraph();

  const menuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!contextMenu) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") closeContextMenu();
    }
    function onClick(e: MouseEvent) {
      if (menuRef.current?.contains(e.target as Node)) return;
      closeContextMenu();
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [contextMenu, closeContextMenu]);

  const node = useMemo(() => {
    if (!contextMenu || !data) return null;
    return data.nodes.find((n) => n.id === contextMenu.nodeId) ?? null;
  }, [contextMenu, data]);

  if (!contextMenu || !node) return null;

  const kind = node.kinds[0] ?? "Unknown";
  const config = getHexConfig(kind);
  const Icon = config.icon;
  const name = String(
    node.properties?.name ??
      node.properties?.uri ??
      node.properties?.path ??
      node.id.slice(0, 12),
  );

  // Viewport-aware positioning: if the click is near the right edge, open
  // leftwards. If near the bottom, open upwards.
  const vw = typeof window !== "undefined" ? window.innerWidth : 1920;
  const vh = typeof window !== "undefined" ? window.innerHeight : 1080;
  const left =
    contextMenu.x + MENU_WIDTH > vw - 16
      ? Math.max(8, contextMenu.x - MENU_WIDTH)
      : contextMenu.x;
  const top =
    contextMenu.y + MENU_HEIGHT_ESTIMATE > vh - 16
      ? Math.max(8, contextMenu.y - MENU_HEIGHT_ESTIMATE)
      : contextMenu.y;

  // --- action handlers ---

  function handleSetBlastSource() {
    setActiveLens("blast-radius");
    setBlastRadiusSource(node!.id);
    selectNode(node!.id);
    closeContextMenu();
  }

  function handleFocusNeighborhood() {
    if (!data) return;
    const ids = bfsNeighborhood(node!.id, data.edges, 2, "both");
    setHighlight({
      nodeIds: Array.from(ids.nodes),
      edgeIds: Array.from(ids.edges),
      title: `2-hop neighborhood · ${name}`,
    });
    selectNode(node!.id);
    closeContextMenu();
  }

  function handleShowInbound() {
    if (!data) return;
    const ids = bfsNeighborhood(node!.id, data.edges, 6, "in");
    setHighlight({
      nodeIds: Array.from(ids.nodes),
      edgeIds: Array.from(ids.edges),
      title: `Inbound reach · ${name}`,
    });
    selectNode(node!.id);
    closeContextMenu();
  }

  function handleShowOutbound() {
    if (!data) return;
    const ids = bfsNeighborhood(node!.id, data.edges, 6, "out");
    setHighlight({
      nodeIds: Array.from(ids.nodes),
      edgeIds: Array.from(ids.edges),
      title: `Outbound reach · ${name}`,
    });
    selectNode(node!.id);
    closeContextMenu();
  }

  function handleViewEvidence() {
    selectNode(node!.id);
    openDrawer("evidence");
    closeContextMenu();
  }

  function handleViewRemediation() {
    selectNode(node!.id);
    openDrawer("remediation");
    closeContextMenu();
  }

  function handleToggleOwned() {
    toggleOwned(node!.id);
    closeContextMenu();
  }

  function handleToggleHighValue() {
    toggleHighValue(node!.id);
    closeContextMenu();
  }

  function handleCopyObjectId() {
    void navigator.clipboard.writeText(node!.id);
    closeContextMenu();
  }

  function handleCopyAsMarkdown() {
    const md = formatNodeAsMarkdown(
      node!,
      config.kindTag,
      owned,
      highValue,
    );
    void navigator.clipboard.writeText(md);
    closeContextMenu();
  }

  // Contextual label for the blast radius action.
  let blastRadiusLabel = "Set as blast radius source";
  if (activeLens === "blast-radius") {
    if (blastSourceId === node.id) {
      blastRadiusLabel = "Refocus here";
    } else {
      blastRadiusLabel = "Use as blast radius source";
    }
  }

  const owned = isOwned(node.id);
  const highValue = isHighValue(node.id);

  const entries: MenuEntry[] = [
    { type: "section", label: "Focus" },
    {
      type: "item",
      icon: Radar,
      label: blastRadiusLabel,
      onSelect: handleSetBlastSource,
    },
    {
      type: "item",
      icon: Crosshair,
      label: "Focus 2-hop neighborhood",
      onSelect: handleFocusNeighborhood,
    },
    {
      type: "item",
      icon: ArrowDown,
      label: "Show what reaches this",
      onSelect: handleShowInbound,
    },
    {
      type: "item",
      icon: ArrowUp,
      label: "Show what this reaches",
      onSelect: handleShowOutbound,
    },
    { type: "divider" },
    { type: "section", label: "Inspect" },
    {
      type: "item",
      icon: FileLock2,
      label: "View evidence",
      onSelect: handleViewEvidence,
    },
    {
      type: "item",
      icon: Shield,
      label: "View remediation",
      onSelect: handleViewRemediation,
    },
    { type: "divider" },
    { type: "section", label: "Mark" },
    {
      type: "item",
      icon: Target,
      label: owned ? "Unmark Owned" : "Mark as Owned",
      onSelect: handleToggleOwned,
      active: owned,
      destructive: !owned,
    },
    {
      type: "item",
      icon: Crown,
      label: highValue ? "Unmark High Value" : "Mark as High Value",
      onSelect: handleToggleHighValue,
      active: highValue,
    },
    { type: "divider" },
    { type: "section", label: "Copy" },
    {
      type: "item",
      icon: Copy,
      label: "Copy objectid",
      onSelect: handleCopyObjectId,
    },
    {
      type: "item",
      icon: FileText,
      label: "Copy as Markdown",
      onSelect: handleCopyAsMarkdown,
    },
  ];

  return (
    <div
      ref={menuRef}
      role="menu"
      className={cn(
        "fixed z-[70] overflow-hidden rounded-lg glass shadow-2xl",
        "animate-in fade-in zoom-in-95 duration-100",
      )}
      style={{ left, top, width: MENU_WIDTH }}
      onContextMenu={(e) => e.preventDefault()}
    >
      {/* Header */}
      <div
        className="flex items-center gap-2.5 border-b border-border px-3 py-2.5"
        style={{ borderTopColor: config.strokeColor, borderTopWidth: 2 }}
      >
        <div
          className="flex h-7 w-7 items-center justify-center rounded-md border"
          style={{
            borderColor: config.strokeColor,
            background: `${config.strokeColor}15`,
          }}
        >
          <Icon
            className="h-3.5 w-3.5"
            style={{ color: config.strokeColor }}
            strokeWidth={2.25}
          />
        </div>
        <div className="flex min-w-0 flex-col">
          <div
            className="text-[10px] uppercase tracking-widest"
            style={{ color: config.strokeColor }}
          >
            {config.kindTag}
          </div>
          <div className="truncate text-xs font-semibold text-foreground">
            {name}
          </div>
        </div>
        {owned && (
          <Target
            className="ml-auto h-3 w-3 flex-shrink-0 text-red-400"
            strokeWidth={2.75}
          />
        )}
        {highValue && (
          <Crown
            className="ml-auto h-3 w-3 flex-shrink-0 text-yellow-400"
            strokeWidth={2.5}
            fill="currentColor"
            fillOpacity={0.25}
          />
        )}
      </div>

      {/* Items */}
      <div className="py-1">
        {entries.map((entry, i) => {
          if (entry.type === "divider") {
            return (
              <div
                key={`div-${i}`}
                className="my-1 border-t border-border"
              />
            );
          }
          if (entry.type === "section") {
            return (
              <div
                key={`sec-${i}`}
                className="px-3 pt-2 pb-1 text-[9px] font-semibold uppercase tracking-widest text-muted-foreground/70"
              >
                {entry.label}
              </div>
            );
          }
          const ItemIcon = entry.icon;
          return (
            <button
              key={`item-${i}-${entry.label}`}
              role="menuitem"
              onClick={(e) => {
                e.stopPropagation();
                entry.onSelect();
              }}
              disabled={entry.disabled}
              className={cn(
                "group/mi flex w-full items-center gap-2.5 px-3 py-1.5 text-left text-xs",
                "transition-colors",
                !entry.disabled && !entry.active && "text-foreground hover:bg-muted hover:text-foreground",
                entry.active && "text-foreground bg-muted",
                entry.disabled && "text-muted-foreground/70 cursor-not-allowed",
              )}
            >
              <ItemIcon
                className={cn(
                  "h-3.5 w-3.5 flex-shrink-0",
                  entry.active && "text-red-400",
                )}
                strokeWidth={2.25}
              />
              <span className="flex-1">{entry.label}</span>
            </button>
          );
        })}
      </div>

      {/* Footer hint */}
      <div className="border-t border-border bg-muted/40 px-3 py-1.5 text-[9px] uppercase tracking-widest text-muted-foreground/70 flex items-center gap-2">
        <Focus className="h-2.5 w-2.5" strokeWidth={2.5} />
        <span>Esc to close</span>
      </div>
    </div>
  );
}

// --- helpers ---

const MD_SKIP_KEYS = new Set([
  "objectid",
  "scan_id",
  "last_seen",
  "created_at",
  "description_hash",
  "card_hash",
  "previous_description_hash",
]);

const MD_PRIORITY_KEYS = [
  "name",
  "endpoint",
  "uri",
  "path",
  "hostname",
  "transport",
  "protocol_version",
  "auth_method",
  "is_pinned",
  "is_exposed",
  "is_signed",
  "signature_valid",
  "high_entropy",
  "has_injection_patterns",
  "has_cross_references",
  "is_suspicious",
  "sensitivity",
  "risk_score",
  "framework",
  "provider",
  "version",
  "tool_count",
  "skill_count",
  "server_count",
  "capability_surface",
];

/**
 * Format a node as a clean Markdown dump suitable for pasting into a
 * Jira ticket, GitHub issue, or incident report. Priority properties
 * (name, endpoint, auth_method, risk_score, etc.) are listed first in
 * a stable order; everything else follows alphabetically. Noise fields
 * (hashes, timestamps, scan_id) are skipped.
 */
function formatNodeAsMarkdown(
  node: { id: string; kinds: string[]; properties: Record<string, unknown> },
  kindTag: string,
  owned: boolean,
  highValue: boolean,
): string {
  const props = node.properties ?? {};
  const name =
    (typeof props.name === "string" && props.name) ||
    (typeof props.uri === "string" && props.uri) ||
    (typeof props.path === "string" && props.path) ||
    node.id.slice(0, 12);

  const lines: string[] = [];
  lines.push(`## ${name}`);
  lines.push("");
  lines.push(`**Kind:** ${kindTag.replace(/\s+/g, " ")}`);
  lines.push(`**Objectid:** \`${node.id}\``);

  const marks: string[] = [];
  if (owned) marks.push("🎯 Owned");
  if (highValue) marks.push("👑 High Value");
  if (marks.length > 0) {
    lines.push(`**Marked:** ${marks.join(" · ")}`);
  }

  lines.push("");
  lines.push("**Properties:**");

  const seen = new Set<string>();
  const bullets: string[] = [];

  for (const key of MD_PRIORITY_KEYS) {
    if (MD_SKIP_KEYS.has(key)) continue;
    if (!(key in props)) continue;
    const value = props[key];
    if (value === null || value === undefined || value === "") continue;
    seen.add(key);
    bullets.push(`- \`${key}\`: ${formatValue(value)}`);
  }

  const remaining = Object.keys(props)
    .filter((k) => !MD_SKIP_KEYS.has(k) && !seen.has(k))
    .sort();
  for (const key of remaining) {
    const value = props[key];
    if (value === null || value === undefined || value === "") continue;
    bullets.push(`- \`${key}\`: ${formatValue(value)}`);
  }

  if (bullets.length === 0) {
    lines.push("_(no properties recorded)_");
  } else {
    lines.push(...bullets);
  }

  lines.push("");
  lines.push("_Exported from AgentHound Explorer_");
  return lines.join("\n");
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "`true`" : "`false`";
  if (typeof v === "number") return `\`${v}\``;
  if (typeof v === "string") {
    // Wrap multi-line strings in a fenced block so tickets render them cleanly.
    if (v.includes("\n")) return `\n\n  \`\`\`\n  ${v.replace(/\n/g, "\n  ")}\n  \`\`\``;
    return v;
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return "_(empty)_";
    return v.map((x) => `\`${String(x)}\``).join(", ");
  }
  if (typeof v === "object") {
    try {
      return `\`${JSON.stringify(v)}\``;
    } catch {
      return String(v);
    }
  }
  return String(v);
}

type Direction = "in" | "out" | "both";

function bfsNeighborhood(
  startId: string,
  edges: APIEdge[],
  maxHops: number,
  direction: Direction,
): { nodes: Set<string>; edges: Set<string> } {
  const visitedNodes = new Set<string>([startId]);
  const visitedEdges = new Set<string>();
  let frontier = [startId];
  for (let hop = 0; hop < maxHops && frontier.length > 0; hop++) {
    const next: string[] = [];
    for (const current of frontier) {
      for (const e of edges) {
        const edgeKey = `${e.source}|${e.target}|${e.kind}`;
        const touchesCurrent = e.source === current || e.target === current;
        if (!touchesCurrent) continue;
        if (direction !== "in" && e.source === current) {
          if (!visitedNodes.has(e.target)) {
            visitedNodes.add(e.target);
            next.push(e.target);
          }
          visitedEdges.add(edgeKey);
        }
        if (direction !== "out" && e.target === current) {
          if (!visitedNodes.has(e.source)) {
            visitedNodes.add(e.source);
            next.push(e.source);
          }
          visitedEdges.add(edgeKey);
        }
      }
    }
    frontier = next;
  }
  return { nodes: visitedNodes, edges: visitedEdges };
}

import { useExplorerStore } from "@/store/explorer";
import { getLens } from "@/lib/explorer/lens-config";
import { cn } from "@/lib/utils";

interface LegendItem {
  color: string;
  label: string;
  dashed?: boolean;
  thick?: boolean;
}

const LEGEND_BY_LENS: Record<string, LegendItem[]> = {
  topology: [
    { color: "#06B6D4", label: "Agent" },
    { color: "#10B981", label: "MCP Server" },
    { color: "#F59E0B", label: "Tool" },
    { color: "#EF4444", label: "Resource" },
    { color: "#334155", label: "Trust edge" },
  ],
  "attack-surface": [
    { color: "#EF4444", label: "Critical reach", thick: true },
    { color: "#F97316", label: "High reach", thick: true },
    { color: "#EAB308", label: "Medium" },
    { color: "#94A3B8", label: "Low" },
  ],
  critical: [
    { color: "#EF4444", label: "Critical path", thick: true },
    { color: "#A855F7", label: "Cross-protocol", dashed: true },
    { color: "#1E293B", label: "Dimmed context" },
  ],
  "cross-protocol": [
    { color: "#A855F7", label: "Cross-protocol edge", dashed: true, thick: true },
    { color: "#06B6D4", label: "A2A Agent" },
    { color: "#10B981", label: "MCP Server" },
  ],
  credentials: [
    { color: "#EC4899", label: "Credential" },
    { color: "#94A3B8", label: "Identity" },
    { color: "#10B981", label: "MCP Server" },
  ],
  poisoning: [
    { color: "#EAB308", label: "Poisoned tool" },
    { color: "#F97316", label: "Shadowing" },
    { color: "#EF4444", label: "Poisoned instructions" },
  ],
  "blast-radius": [
    { color: "#10B981", label: "Source node", thick: true },
    { color: "#94A3B8", label: "Reachable" },
    { color: "#1E293B", label: "Out of scope" },
  ],
  chokepoints: [
    { color: "#06B6D4", label: "High centrality" },
    { color: "#64748B", label: "Medium centrality" },
    { color: "#334155", label: "Low centrality" },
  ],
};

export function Legend() {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const lens = getLens(activeLens);
  const items = LEGEND_BY_LENS[activeLens] ?? [];

  if (items.length === 0) return null;

  return (
    <div
      className={cn(
        "pointer-events-auto absolute left-6 bottom-12 z-20 rounded-lg",
        "glass px-3 py-2.5 shadow-xl",
      )}
    >
      <div className="mb-2 text-[9px] font-semibold uppercase tracking-widest text-muted-foreground">
        {lens.shortLabel} legend
      </div>
      <div className="space-y-1.5">
        {items.map((item, i) => (
          <div key={i} className="flex items-center gap-2">
            <svg width="28" height="10" className="flex-shrink-0">
              {item.dashed ? (
                <line
                  x1="0"
                  y1="5"
                  x2="28"
                  y2="5"
                  stroke={item.color}
                  strokeWidth={item.thick ? 3 : 2}
                  strokeDasharray="4 3"
                />
              ) : (
                <line
                  x1="0"
                  y1="5"
                  x2="28"
                  y2="5"
                  stroke={item.color}
                  strokeWidth={item.thick ? 3 : 2}
                />
              )}
            </svg>
            <div className="text-[10px] text-foreground">{item.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

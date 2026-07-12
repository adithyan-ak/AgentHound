import { useExplorerStore } from "@features/explorer/model/store";
import { edgeLabel, edgeDescription, getEdgeCategory } from "@entities/edge";
import { EDGE_COLORS } from "@shared/theme/tokens";
import { cn } from "@shared/lib/utils";

const TOOLTIP_WIDTH = 240;

/**
 * Floating tooltip that follows the cursor while hovering an edge. Turns an
 * anonymous colored line into a readable relationship — kind, plain-English
 * meaning, confidence, and the via-path the composite edge summarizes.
 * Suppressed once the edge is selected (the edge drawer takes over).
 */
export function EdgeTooltip() {
  const hovered = useExplorerStore((s) => s.hoveredEdge);
  const selectedId = useExplorerStore((s) => s.selectedEdge?.id ?? null);

  if (!hovered || hovered.id === selectedId) return null;

  const d = hovered.data;
  const category = getEdgeCategory(d.kind);
  const color = EDGE_COLORS[category];

  const props = d.properties ?? {};
  const viaServer = props["via_server"] ? String(props["via_server"]) : "";
  const viaTool = props["via_tool"] ? String(props["via_tool"]) : "";
  const viaCred = props["via_credential"] ? String(props["via_credential"]) : "";
  const hops = typeof props["hops"] === "number" ? (props["hops"] as number) : null;
  const confidence = d.confidence || Number(props["confidence"] ?? 0);
  const configuredReference = props["assertion_type"] === "configured_reference";
  const configurationConfidence =
    configuredReference &&
    props["confidence_scope"] === "configuration_presence";

  const vw = typeof window !== "undefined" ? window.innerWidth : 1920;
  const vh = typeof window !== "undefined" ? window.innerHeight : 1080;
  const left = Math.min(hovered.x + 16, vw - TOOLTIP_WIDTH - 12);
  const top = Math.min(hovered.y + 16, vh - 160);

  return (
    <div
      className="pointer-events-none fixed z-[60] overflow-hidden rounded-md border border-border bg-card/95 backdrop-blur-md elev-3"
      style={{ left, top, width: TOOLTIP_WIDTH }}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute left-0 top-0 h-px w-10"
        style={{ background: color, opacity: 0.9 }}
      />
      <div className="px-3 py-2.5">
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-[1px]" style={{ background: color }} />
          <span
            className="font-mono text-[11px] font-bold uppercase tracking-[0.08em]"
            style={{ color }}
          >
            {edgeLabel(d.kind, { properties: props })}
          </span>
          <span className="ml-auto font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
            {category}
          </span>
        </div>

        <div className="mt-1.5 text-[11px] leading-snug text-foreground/85">
          {configuredReference
            ? "Configuration references this backend; service existence was not probed"
            : edgeDescription(d.kind, {
                properties: props,
                targetKind: d.targetKind,
              })}
        </div>
        {configuredReference && (
          <div className="mt-1.5 rounded border border-amber-400/30 bg-amber-400/10 px-2 py-1 text-[10px] leading-snug text-amber-200">
            Configuration reference observed; backend availability and
            authentication were not directly verified.
          </div>
        )}

        {d.bundledCount > 1 && (
          <div className="mt-1 font-mono text-[10px] text-primary/80">
            +{d.bundledCount - 1} more relationship
            {d.bundledCount - 1 === 1 ? "" : "s"} on this link
          </div>
        )}

        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-muted-foreground">
          {confidence > 0 && (
            <span>
              {configurationConfidence ? "configuration presence" : "conf"}{" "}
              <span className="tabular-nums text-foreground/80">
                {Math.round(confidence * 100)}%
              </span>
            </span>
          )}
          {hops != null && (
            <span>
              <span className="tabular-nums text-foreground/80">{hops}</span> hops
            </span>
          )}
          {d.isCrossProtocol && (
            <span className="text-purple-300">cross-protocol</span>
          )}
          {d.isComposite && <span>composite</span>}
          {configuredReference && <span>configured-only</span>}
        </div>

        {(viaServer || viaTool || viaCred) && (
          <div className="mt-1.5 truncate font-mono text-[10px] text-muted-foreground">
            via{" "}
            <span className="text-foreground/80">
              {[viaServer, viaTool, viaCred].filter(Boolean).join(" / ")}
            </span>
          </div>
        )}

        <div className={cn("mt-2 font-mono text-[9px] uppercase tracking-[0.12em] text-primary/60")}>
          click to inspect →
        </div>
      </div>
    </div>
  );
}

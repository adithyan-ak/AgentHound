import { memo, useEffect, useMemo, useRef, useState } from "react";
import { type NodeProps } from "@xyflow/react";
import { Search, ChevronRight } from "lucide-react";
import type { OrphanClusterData } from "@features/explorer/model/graph";
import {
  getHexConfig,
  HEX_POLYGON_POINTS,
  HEX_NODE_WIDTH,
  HEX_NODE_HEIGHT,
} from "@shared/lib/hex-config";
import { useExplorerStore } from "@features/explorer/model/store";
import { getLens } from "@features/explorer/model/lens-config";
import { cn } from "@shared/lib/utils";
import { EXPLORER_HEX_FILL } from "@shared/theme/tokens";
import { NodeHandles } from "./NodeHandles";

const HOVER_CLOSE_DELAY_MS = 160;

function OrphanClusterNodeComponent({ data }: NodeProps) {
  const d = data as OrphanClusterData;
  const config = getHexConfig(d.kind);
  const Icon = config.icon;

  const selectNode = useExplorerStore((s) => s.selectNode);
  const openDrawer = useExplorerStore((s) => s.openDrawer);
  const activeLens = useExplorerStore((s) => s.activeLens);
  const lensLabel = getLens(activeLens).label.toLowerCase();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const closeTimerRef = useRef<number | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return d.orphanNodes;
    return d.orphanNodes.filter((n) => n.name.toLowerCase().includes(q));
  }, [d.orphanNodes, search]);

  useEffect(() => {
    return () => {
      if (closeTimerRef.current) {
        clearTimeout(closeTimerRef.current);
      }
    };
  }, []);

  function cancelClose() {
    if (closeTimerRef.current) {
      clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
  }

  function scheduleClose() {
    if (closeTimerRef.current) return;
    closeTimerRef.current = window.setTimeout(() => {
      setOpen(false);
      setSearch("");
      closeTimerRef.current = null;
    }, HOVER_CLOSE_DELAY_MS);
  }

  function handleEnter() {
    cancelClose();
    setOpen(true);
  }

  const strokeColor = config.strokeColor;

  return (
    <div
      className="relative flex flex-col items-center select-none"
      style={{ width: HEX_NODE_WIDTH }}
      onMouseEnter={handleEnter}
      onMouseLeave={scheduleClose}
    >
      <div
        role="button"
        tabIndex={0}
        className="relative cursor-pointer rounded-[3px] transition-transform duration-150 hover:scale-[1.08] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/60"
        style={{ width: HEX_NODE_WIDTH, height: HEX_NODE_HEIGHT }}
        aria-label={`${d.count} ${d.kindTag} with no ${lensLabel} edges in this lens. Activate to browse and inspect.`}
        aria-expanded={open}
        onFocus={handleEnter}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setOpen(true);
          } else if (e.key === "Escape") {
            setOpen(false);
            setSearch("");
          }
        }}
      >
        <svg
          width={HEX_NODE_WIDTH}
          height={HEX_NODE_HEIGHT}
          viewBox={`0 0 ${HEX_NODE_WIDTH} ${HEX_NODE_HEIGHT}`}
          className="absolute inset-0 pointer-events-none"
        >
          <g opacity={0.25}>
            <polygon
              points={HEX_POLYGON_POINTS}
              fill="none"
              stroke={strokeColor}
              strokeWidth={2}
              strokeLinejoin="round"
              transform="translate(-6, -3)"
            />
          </g>
          <g opacity={0.45}>
            <polygon
              points={HEX_POLYGON_POINTS}
              fill="none"
              stroke={strokeColor}
              strokeWidth={2}
              strokeLinejoin="round"
              transform="translate(-3, -1.5)"
            />
          </g>
          <polygon
            points={HEX_POLYGON_POINTS}
            fill={EXPLORER_HEX_FILL}
            stroke={strokeColor}
            strokeWidth={2.5}
            strokeLinejoin="round"
            strokeDasharray="4 2.5"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <Icon
            className="h-4 w-4 mb-0.5"
            style={{ color: strokeColor }}
            strokeWidth={2}
          />
          <div
            className="text-[15px] font-bold leading-none tabular-nums"
            style={{ color: strokeColor }}
          >
            {d.count}
          </div>
        </div>
      </div>

      {open && (
        <>
          <div
            className="absolute left-1/2 -translate-x-1/2 h-4 w-[180px]"
            style={{ top: "100%", pointerEvents: "auto" }}
            onMouseEnter={handleEnter}
            onMouseLeave={scheduleClose}
          />
          <div
            className={cn(
              "absolute left-1/2 w-[300px] -translate-x-1/2 overflow-hidden rounded-md border border-border bg-card/95 backdrop-blur-md elev-3",
              "z-[60]",
              "animate-in fade-in zoom-in-95 duration-150",
            )}
            style={{ top: "calc(100% + 14px)" }}
            onMouseEnter={handleEnter}
            onMouseLeave={scheduleClose}
          >
          <div className="relative flex items-center gap-2 border-b border-border px-3 py-2.5">
            <span
              aria-hidden
              className="pointer-events-none absolute inset-x-0 top-0 h-px"
              style={{ background: strokeColor, opacity: 0.7 }}
            />
            <Icon
              className="h-4 w-4"
              style={{ color: strokeColor }}
              strokeWidth={2.25}
            />
            <div className="flex flex-col">
              <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                No {lensLabel} edges
              </div>
              <div className="text-sm font-semibold text-foreground">
                {d.count} {d.kindTag.toLowerCase()}
              </div>
            </div>
          </div>

          {d.orphanNodes.length > 8 && (
            <div className="flex items-center gap-2 border-b border-border bg-black/30 px-3 py-2">
              <Search className="h-3 w-3 text-muted-foreground" strokeWidth={2.5} />
              <input
                autoFocus
                placeholder="filter…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-transparent font-mono text-xs text-foreground placeholder:text-muted-foreground/70 focus:outline-none"
              />
            </div>
          )}

          <div className="max-h-[320px] overflow-y-auto py-1">
            {filtered.length === 0 ? (
              <div className="px-3 py-4 text-center font-mono text-xs uppercase tracking-[0.08em] text-muted-foreground">
                No matches.
              </div>
            ) : (
              filtered.map((n) => (
                <button
                  key={n.id}
                  onClick={(e) => {
                    e.stopPropagation();
                    selectNode(n.id);
                    openDrawer();
                    setOpen(false);
                  }}
                  className={cn(
                    "group/row flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs",
                    "transition-colors hover:bg-white/[0.05]",
                  )}
                >
                  <span
                    className="h-1.5 w-1.5 flex-shrink-0 rounded-[1px]"
                    style={{ background: strokeColor }}
                  />
                  <span className="flex-1 truncate font-mono text-[11px] text-foreground">
                    {n.name}
                  </span>
                  <ChevronRight className="h-3 w-3 flex-shrink-0 text-muted-foreground/70 group-hover/row:text-muted-foreground" />
                </button>
              ))
            )}
          </div>

          <div className="border-t border-border bg-black/20 px-3 py-1.5 font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground/70">
            Hover to browse · click a row to inspect
          </div>
          </div>
        </>
      )}

      <div className="mt-1 flex flex-col items-center text-center">
        <div
          className="text-[10px] font-semibold whitespace-nowrap max-w-[180px] overflow-hidden text-ellipsis"
          style={{
            color: strokeColor,
            textShadow: "0 1px 4px rgba(0,0,0,0.9)",
          }}
        >
          {d.count} UNCONNECTED
        </div>
        <div className="text-[8px] tracking-[0.12em] text-muted-foreground font-medium mt-0.5">
          {d.kindTag}
        </div>
      </div>

      <NodeHandles />
    </div>
  );
}

export const OrphanClusterNode = memo(OrphanClusterNodeComponent);

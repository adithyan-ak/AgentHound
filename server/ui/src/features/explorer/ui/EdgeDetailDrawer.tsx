import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, X, AlertTriangle, FileSearch } from "lucide-react";
import { useExplorerStore } from "@features/explorer/model/store";
import { useExplorerGraph } from "@features/explorer/model/useExplorerGraph";
import {
  getEdgeCategory,
  edgeLabel,
  edgeDescription,
  edgeExploit,
} from "@entities/edge";
import type { BundledEdge } from "@features/explorer/model/graph";
import type { Finding } from "@entities/finding/model";
import { getHexConfig } from "@shared/lib/hex-config";
import { EDGE_COLORS, SEVERITY, SEVERITY_BY_KEY } from "@shared/theme/tokens";
import { cn } from "@shared/lib/utils";
import { useEscapeKey } from "@shared/lib/useEscapeKey";

const HIDDEN_PROPS = new Set(["scan_id", "last_seen", "is_composite"]);

function Endpoint({ id, name, kind }: { id: string; name: string; kind: string }) {
  const config = getHexConfig(kind);
  const Icon = config.icon;
  return (
    <div className="flex min-w-0 items-center gap-2">
      <span
        className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-[3px] border"
        style={{ borderColor: config.strokeColor, background: `${config.strokeColor}15` }}
      >
        <Icon className="h-3.5 w-3.5" style={{ color: config.strokeColor }} strokeWidth={2.25} />
      </span>
      <div className="flex min-w-0 flex-col">
        <span className="truncate text-xs font-semibold text-foreground" title={name}>
          {name || id.slice(0, 12)}
        </span>
        <span
          className="font-mono text-[9px] uppercase tracking-[0.12em]"
          style={{ color: config.strokeColor }}
        >
          {config.kindTag}
        </span>
      </div>
    </div>
  );
}

function RelationshipCard({ edge }: { edge: BundledEdge }) {
  const category = getEdgeCategory(edge.kind);
  const color = EDGE_COLORS[category];
  const exploit = edgeExploit(edge.kind);
  const props = edge.properties ?? {};
  const exploitSeverity =
    edge.kind === "CAN_REACH" && props["cross_protocol"] === true
      ? SEVERITY.medium
      : SEVERITY.critical;
  const entries = Object.entries(props).filter(
    ([k, v]) => !HIDDEN_PROPS.has(k) && v != null && v !== "",
  );

  return (
    <div
      className="rounded-[3px] border border-border/70 bg-black/20 p-3"
      style={{ boxShadow: `inset 2px 0 0 0 ${color}` }}
    >
      <div className="flex items-center gap-2">
        <span
          className="rounded-[2px] border px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-[0.06em]"
          style={{ color, borderColor: `${color}55`, background: `${color}14` }}
        >
          {edgeLabel(edge.kind)}
        </span>
        <span className="font-mono text-[10px] text-muted-foreground">
          {edgeDescription(edge.kind)}
        </span>
      </div>
      {props["assertion_type"] === "configured_reference" && (
        <div className="mt-2 rounded-[3px] border border-amber-400/30 bg-amber-400/10 px-2.5 py-2 text-[11px] leading-relaxed text-amber-100">
          Configuration reference only. The target service and its
          authentication were not directly verified.
        </div>
      )}

      {exploit && (
        <div
          className="mt-2 rounded-[3px] bg-black/30 p-2.5"
          style={{ boxShadow: `inset 2px 0 0 0 ${exploitSeverity.solid}` }}
        >
          <div
            className="mb-1 flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em]"
            style={{ color: exploitSeverity.text }}
          >
            <AlertTriangle className="h-3 w-3" />
            {exploit.title}
          </div>
          <p className="text-[11px] leading-relaxed text-foreground/80">{exploit.detail}</p>
        </div>
      )}

      {entries.length > 0 && (
        <div className="mt-2 grid grid-cols-[repeat(auto-fill,minmax(11rem,1fr))] gap-x-4 gap-y-1">
          {entries.map(([key, val]) => (
            <div key={key} className="flex items-baseline gap-1.5">
              <span className="font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground">
                {key.replace(/_/g, " ")}
              </span>
              <span className="truncate font-mono text-[10px] text-foreground" title={String(val)}>
                {typeof val === "boolean" ? (val ? "yes" : "no") : String(val)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function EdgeDetailDrawer() {
  const navigate = useNavigate();
  const selectedEdge = useExplorerStore((s) => s.selectedEdge);
  const selectEdge = useExplorerStore((s) => s.selectEdge);
  const { data } = useExplorerGraph();

  useEscapeKey(() => selectEdge(null), { enabled: !!selectedEdge });

  const nodeById = useMemo(() => {
    const m = new Map<string, { name: string; kind: string }>();
    for (const n of data?.nodes ?? []) {
      const name = String(
        n.properties?.name ?? n.properties?.uri ?? n.properties?.path ?? n.id.slice(0, 12),
      );
      m.set(n.id, { name, kind: n.kinds[0] ?? "" });
    }
    return m;
  }, [data?.nodes]);

  const relatedFindings = useMemo<Finding[]>(() => {
    if (!selectedEdge || !data) return [];
    const kinds = new Set<string>(selectedEdge.data.bundledKinds);
    return data.findings.filter(
      (f) =>
        f.source_id === selectedEdge.source &&
        f.target_id === selectedEdge.target &&
        kinds.has(f.edge_kind),
    );
  }, [selectedEdge, data]);

  if (!selectedEdge) return null;

  const d = selectedEdge.data;
  const category = getEdgeCategory(d.kind);
  const color = EDGE_COLORS[category];
  const src = nodeById.get(selectedEdge.source) ?? { name: selectedEdge.source, kind: d.sourceKind };
  const tgt = nodeById.get(selectedEdge.target) ?? { name: selectedEdge.target, kind: d.targetKind };

  return (
    <div
      className={cn(
        "pointer-events-auto absolute bottom-0 left-0 right-0 z-30",
        "border-t border-border bg-card/95 shadow-[0_-8px_40px_-8px_rgba(0,0,0,0.8)] backdrop-blur-md",
        "animate-in slide-in-from-bottom-4 fade-in duration-200",
      )}
      style={{ height: "40vh", minHeight: 320 }}
      role="dialog"
      aria-label="Edge details"
    >
      <div className="flex h-full flex-col">
        <div className="relative flex items-center gap-3 border-b border-border bg-black/20 px-4 py-3">
          <span
            aria-hidden
            className="pointer-events-none absolute left-0 top-0 h-px w-14"
            style={{ background: color, opacity: 0.9 }}
          />
          <Endpoint id={selectedEdge.source} name={src.name} kind={src.kind} />
          <div className="flex flex-col items-center">
            <span
              className="rounded-[2px] border px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-[0.06em]"
              style={{ color, borderColor: `${color}55`, background: `${color}14` }}
            >
              {edgeLabel(d.kind)}
            </span>
            <ArrowRight className="mt-1 h-3.5 w-3.5" style={{ color }} />
          </div>
          <Endpoint id={selectedEdge.target} name={tgt.name} kind={tgt.kind} />

          <div className="ml-3 flex items-center gap-1.5">
            {d.isCrossProtocol && (
              <span className="rounded-[2px] bg-purple-500/15 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-[0.08em] text-purple-300">
                cross-protocol
              </span>
            )}
            {d.isComposite && (
              <span className="rounded-[2px] border border-border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">
                composite
              </span>
            )}
          </div>

          <button
            onClick={() => selectEdge(null)}
            className="ml-auto flex h-7 w-7 items-center justify-center rounded-[3px] text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
            aria-label="Close edge details"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-auto px-5 py-4">
          <div className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            {d.bundledEdges.length} relationship{d.bundledEdges.length === 1 ? "" : "s"} on this link
          </div>
          <div className="space-y-2">
            {d.bundledEdges.map((be, i) => (
              <RelationshipCard key={`${be.kind}-${i}`} edge={be} />
            ))}
          </div>

          {relatedFindings.length > 0 && (
            <div className="mt-4">
              <div className="mb-2 flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                <FileSearch className="h-3 w-3" />
                {relatedFindings.length} finding{relatedFindings.length === 1 ? "" : "s"} on this edge
              </div>
              <div className="space-y-1">
                {relatedFindings.map((f) => {
                  const sev = SEVERITY_BY_KEY[f.severity] ?? SEVERITY.low;
                  return (
                    <button
                      key={f.id}
                      onClick={() => navigate(`/findings/${f.id}`)}
                      className="flex w-full items-center gap-2 rounded-[3px] border border-border bg-black/30 px-2.5 py-2 text-left transition-colors hover:border-mauve-7 hover:bg-white/[0.03]"
                    >
                      <span
                        className="h-2 w-2 flex-shrink-0 rounded-[1px]"
                        style={{ backgroundColor: sev.solid }}
                      />
                      <span
                        className="w-16 flex-shrink-0 font-mono text-[10px] font-bold uppercase tracking-[0.08em]"
                        style={{ color: sev.solid }}
                      >
                        {f.severity}
                      </span>
                      <span className="truncate text-xs text-foreground">{f.title}</span>
                      <ArrowRight className="ml-auto h-3 w-3 flex-shrink-0 text-primary/50" />
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

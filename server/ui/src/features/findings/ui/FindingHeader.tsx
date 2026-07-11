import { useNavigate } from "react-router-dom";
import { useState, type ReactNode } from "react";
import { ArrowLeft, ArrowRight, Compass, Copy, Check } from "lucide-react";
import { MiniHexIcon } from "./MiniHexIcon";
import { TriageControl } from "./TriageControl";
import { ATLAS_TITLES } from "../lib/owasp-titles";
import { cn } from "@shared/lib/utils";
import { SEVERITY, SEVERITY_BY_KEY } from "@shared/theme/tokens";
import { useTriage } from "@entities/finding";
import type { FindingDetail } from "@entities/finding/model";
import type { TriageStatus } from "@shared/model/triage";

interface FindingHeaderProps {
  detail: FindingDetail;
  prevId: string | null;
  nextId: string | null;
  onCopyReport: () => void;
}

const consoleBtn =
  "inline-flex h-8 items-center gap-1.5 rounded-[3px] border border-border bg-black/30 px-2.5 font-mono text-[11px] uppercase tracking-[0.08em] text-foreground/80 transition-colors hover:border-primary/50 hover:bg-primary/10 hover:text-primary disabled:pointer-events-none disabled:opacity-40";

function Chip({
  children,
  className,
  title,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded-[2px] border border-border bg-black/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function FindingHeader({ detail, prevId, nextId, onCopyReport }: FindingHeaderProps) {
  const navigate = useNavigate();
  const f = detail.finding;
  const sev = SEVERITY_BY_KEY[f.severity] ?? SEVERITY.low;
  const color = sev.solid;
  const [copied, setCopied] = useState(false);

  // The detail's finding comes from the graph (no inline triage), so the
  // dossier control fetches the standalone triage state for this row.
  const { data: triage } = useTriage(f.id);
  const triageStatus = (triage?.status as TriageStatus) ?? "new";

  const path = detail.attack_path;
  const hops =
    path?.shape === "linear" &&
    path.direction === "forward" &&
    path.continuity.state === "continuous" &&
    path.completeness.state === "complete"
      ? path.edges.length
      : null;

  function handleCopy() {
    onCopyReport();
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <section
      className="card-elevated relative overflow-hidden rounded-md"
      style={{
        boxShadow: `inset 2px 0 0 0 ${color}, 0 1px 0 0 rgb(255 255 255 / 0.03) inset, 0 1px 2px 0 rgb(0 0 0 / 0.5)`,
      }}
    >
      <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.05]" />
      <span
        aria-hidden
        className="pointer-events-none absolute left-0 top-0 h-px w-14"
        style={{ backgroundColor: color, opacity: 0.9 }}
      />

      <div className="px-4 py-3.5">
        {/* Breadcrumb + nav */}
        <div className="mb-3 flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
            <button
              onClick={() => navigate("/findings")}
              className="transition-colors hover:text-primary"
            >
              Findings
            </button>
            <span className="text-primary/50">/</span>
            <span style={{ color }}>{f.severity}</span>
            <span className="text-primary/50">/</span>
            <span className="max-w-[320px] truncate normal-case tracking-normal text-foreground/80">
              {f.title}
            </span>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              className={consoleBtn}
              disabled={!prevId}
              onClick={() => prevId && navigate(`/findings/${prevId}`)}
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Prev
            </button>
            <button
              className={consoleBtn}
              disabled={!nextId}
              onClick={() => nextId && navigate(`/findings/${nextId}`)}
            >
              Next <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* Severity + title + actions */}
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <span
              className="inline-flex items-center gap-1.5 rounded-[2px] px-2 py-0.5"
              style={{ backgroundColor: `${color}1A`, color, boxShadow: `inset 0 0 0 1px ${color}55` }}
            >
              <span
                className="h-2 w-2 rounded-[1px]"
                style={{ backgroundColor: color, boxShadow: `0 0 6px -1px ${color}` }}
              />
              <span className="font-mono text-[10px] font-bold uppercase tracking-[0.14em]">
                {sev.label}
              </span>
            </span>

            <h1 className="mt-2 text-[19px] font-semibold leading-snug tracking-tight text-foreground">
              {f.title}
            </h1>

            {/* Source -> Target */}
            <div className="mt-2.5 flex flex-wrap items-center gap-2 font-mono text-sm">
              <MiniHexIcon kind={f.source_kind} />
              <span className="font-medium text-foreground">
                {f.source_name || f.source_id.slice(0, 12)}
              </span>
              <ArrowRight className="h-3.5 w-3.5 text-primary/50" />
              <MiniHexIcon kind={f.target_kind} />
              <span className="font-medium text-foreground">
                {f.target_name || f.target_id.slice(0, 12)}
              </span>
            </div>

            {/* Metadata chips */}
            <div className="mt-3 flex flex-wrap items-center gap-1.5">
              <Chip>
                <span className="text-primary/70">ID</span> {f.id.slice(0, 8)}
              </Chip>
              {typeof hops === "number" && (
                <Chip>
                  <span className="tabular-nums">{hops}</span> hops
                </Chip>
              )}
              <Chip>
                <span className="tabular-nums">{Math.round(f.confidence * 100)}%</span> conf
              </Chip>
              <Chip>{(f.variant ?? "unknown").replace(/_/g, " ")}</Chip>
              <Chip>{(f.evidence?.state ?? "unknown").replace(/_/g, " ")}</Chip>
              {detail.snapshot?.stale && (
                <Chip className="text-amber-400/90">
                  stale published snapshot
                </Chip>
              )}
              {f.owasp_map?.map((tag) => (
                <Chip key={tag} className="text-primary/80">
                  {tag}
                </Chip>
              ))}
              {f.atlas_map?.map((tag) => (
                <Chip key={tag} className="text-amber-400/90" title={ATLAS_TITLES[tag] ?? tag}>
                  {tag}
                </Chip>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex shrink-0 flex-col items-end gap-2">
            <TriageControl findingId={f.id} status={triageStatus} />
            <button
              className={consoleBtn}
              onClick={() => navigate(`/explorer?finding=${f.id}`)}
            >
              <Compass className="h-3.5 w-3.5" /> View in Explorer
            </button>
            <button className={consoleBtn} onClick={handleCopy}>
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" /> Copy Report
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

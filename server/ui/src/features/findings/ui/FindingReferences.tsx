import { useNavigate } from "react-router-dom";
import { BookMarked } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import { useFindings } from "@entities/finding";
import { ATLAS_TITLES, OWASP_TITLES } from "../lib/owasp-titles";
import { SEVERITY, SEVERITY_BY_KEY } from "@shared/theme/tokens";
import type { Finding } from "@entities/finding/model";

interface FindingReferencesProps {
  finding: Finding;
}

export function FindingReferences({ finding }: FindingReferencesProps) {
  const navigate = useNavigate();
  const { data: allFindings } = useFindings();

  const related = (allFindings ?? [])
    .filter(
      (f) =>
        f.id !== finding.id &&
        (f.source_id === finding.source_id ||
          f.target_id === finding.target_id ||
          f.source_id === finding.target_id ||
          f.target_id === finding.source_id),
    )
    .slice(0, 5);

  return (
    <WidgetCard title="References" icon={BookMarked}>
      {finding.owasp_map.length > 0 && (
        <div className="mb-4 space-y-1.5">
          {finding.owasp_map.map((tag) => (
            <div key={tag} className="flex items-baseline gap-2 text-xs">
              <span className="flex-shrink-0 rounded-[2px] border border-border bg-black/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.06em] text-primary/80">
                {tag}
              </span>
              <span className="text-muted-foreground">{OWASP_TITLES[tag] ?? tag}</span>
            </div>
          ))}
        </div>
      )}

      {(finding.atlas_map?.length ?? 0) > 0 && (
        <div className="mb-4 space-y-1.5">
          {finding.atlas_map?.map((tag) => (
            <a
              key={tag}
              href={`https://atlas.mitre.org/techniques/${tag}`}
              target="_blank"
              rel="noreferrer"
              className="flex items-baseline gap-2 text-xs transition-colors hover:text-foreground"
            >
              <span className="flex-shrink-0 rounded-[2px] border border-border bg-black/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.06em] text-amber-400/90">
                {tag}
              </span>
              <span className="text-muted-foreground">{ATLAS_TITLES[tag] ?? tag}</span>
            </a>
          ))}
        </div>
      )}

      <div className="mb-3 font-mono text-[11px]">
        <span className="uppercase tracking-[0.1em] text-muted-foreground">Finding ID</span>{" "}
        <span className="text-foreground">{finding.id}</span>
      </div>

      {related.length > 0 && (
        <>
          <div className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Related ({related.length})
          </div>
          <div className="space-y-0.5">
            {related.map((rf) => {
              const color = (SEVERITY_BY_KEY[rf.severity] ?? SEVERITY.low).solid;
              return (
                <button
                  key={rf.id}
                  onClick={() => navigate(`/findings/${rf.id}`)}
                  className="flex w-full items-center gap-2 rounded-[2px] px-2 py-1.5 text-left transition-colors hover:bg-white/[0.04]"
                >
                  <span
                    className="h-2 w-2 flex-shrink-0 rounded-[1px]"
                    style={{ backgroundColor: color }}
                  />
                  <span
                    className="w-14 flex-shrink-0 font-mono text-[10px] font-bold uppercase tracking-[0.08em]"
                    style={{ color }}
                  >
                    {rf.severity}
                  </span>
                  <span className="truncate text-xs text-foreground">{rf.title}</span>
                </button>
              );
            })}
          </div>
        </>
      )}
    </WidgetCard>
  );
}

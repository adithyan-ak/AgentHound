import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { fetchFindings } from "@/api/analysis";
import { OWASP_TITLES } from "@/lib/findings/owasp-titles";
import { cn } from "@/lib/utils";
import { SEVERITY } from "@/theme/tokens";
import type { Finding } from "@/api/types";

interface FindingReferencesProps {
  finding: Finding;
}

export function FindingReferences({ finding }: FindingReferencesProps) {
  const navigate = useNavigate();
  const { data: allFindings } = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  const related = (allFindings ?? []).filter(
    (f) =>
      f.id !== finding.id &&
      (f.source_id === finding.source_id ||
        f.target_id === finding.target_id ||
        f.source_id === finding.target_id ||
        f.target_id === finding.source_id),
  ).slice(0, 5);

  return (
    <div className="rounded-lg border border-border p-4">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-3">
        References
      </div>

      {finding.owasp_map.length > 0 && (
        <div className="space-y-1.5 mb-4">
          {finding.owasp_map.map((tag) => (
            <div key={tag} className="flex items-baseline gap-2 text-xs">
              <Badge variant="secondary" className="text-[10px] font-mono flex-shrink-0">
                {tag}
              </Badge>
              <span className="text-muted-foreground">{OWASP_TITLES[tag] ?? tag}</span>
            </div>
          ))}
        </div>
      )}

      <div className="text-xs text-muted-foreground mb-3">
        Finding ID: <span className="font-mono text-foreground">{finding.id}</span>
      </div>

      {related.length > 0 && (
        <>
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-2">
            Related Findings ({related.length})
          </div>
          <div className="space-y-1">
            {related.map((rf) => (
              <button
                key={rf.id}
                onClick={() => navigate(`/findings/${rf.id}`)}
                className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded hover:bg-muted/50 transition-colors text-xs"
              >
                <div className={cn("h-2 w-2 rounded-full flex-shrink-0", (SEVERITY[rf.severity] ?? SEVERITY.low!).dotClass)} />
                <span className="text-[10px] uppercase font-bold text-muted-foreground w-14">
                  {rf.severity}
                </span>
                <span className="text-foreground truncate">{rf.title}</span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { fetchFindings } from "@/api/analysis";
import { cn } from "@/lib/utils";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { InfoTip } from "./InfoTip";

const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-900/60 text-red-300 border-red-700",
  high: "bg-orange-900/60 text-orange-300 border-orange-700",
  medium: "bg-yellow-900/60 text-yellow-300 border-yellow-700",
  low: "bg-muted text-muted-foreground border-border",
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export function TopFindings() {
  const navigate = useNavigate();

  const { data: findings, isLoading } = useQuery({
    queryKey: ["dashboard", "findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  const top = (findings ?? [])
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .sort(
      (a, b) =>
        (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
        (b.confidence ?? 0) - (a.confidence ?? 0),
    )
    .slice(0, 10);

  function openFinding(f: (typeof top)[number]) {
    navigate(`/findings/${f.id}`);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-sm font-medium">
          Top Findings
          <InfoTip text="Most critical security findings sorted by severity and confidence. Click any finding to see the full attack path, evidence, and remediation steps." />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : top.length === 0 ? (
          <div className="flex h-48 items-center justify-center text-muted-foreground">
            No critical findings
          </div>
        ) : (
          <ul className="space-y-2">
            {top.map((f) => (
              <li key={f.id}>
                <button
                  onClick={() => openFinding(f)}
                  className="w-full rounded border border-border bg-background/50 px-3 py-2 text-left transition-colors hover:bg-accent hover:border-primary/40 cursor-pointer"
                >
                  <div className="flex items-start gap-2">
                    <Badge
                      variant="outline"
                      className={cn(
                        "mt-0.5 shrink-0 text-[10px] font-semibold uppercase",
                        SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.low,
                      )}
                    >
                      {f.severity}
                    </Badge>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-foreground">
                        {f.title}
                      </p>
                      <p className="truncate text-xs text-muted-foreground">
                        {f.source_name} &rarr; {f.target_name}
                      </p>
                      {f.owasp_map && f.owasp_map.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {f.owasp_map.map((tag) => (
                            <Badge
                              key={tag}
                              variant="secondary"
                              className="text-[10px]"
                            >
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

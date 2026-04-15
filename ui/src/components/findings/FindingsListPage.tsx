import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { ArrowRight, AlertTriangle, Search } from "lucide-react";
import { fetchFindings } from "@/api/analysis";
import type { Finding } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { MiniHexIcon } from "@/components/findings/MiniHexIcon";
import { cn } from "@/lib/utils";
import { SEVERITY } from "@/theme/tokens";

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;

export function FindingsListPage() {
  const navigate = useNavigate();
  const [activeSeverities, setActiveSeverities] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  function toggleSeverity(level: string) {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(level)) {
        next.delete(level);
      } else {
        next.add(level);
      }
      return next;
    });
  }

  const filtered = useMemo(() => {
    if (!findings) return [];
    const q = search.toLowerCase();
    return findings
      .filter((f) => {
        if (activeSeverities.size > 0 && !activeSeverities.has(f.severity)) return false;
        if (q) {
          return (
            f.title.toLowerCase().includes(q) ||
            f.description.toLowerCase().includes(q) ||
            f.source_name.toLowerCase().includes(q) ||
            f.target_name.toLowerCase().includes(q)
          );
        }
        return true;
      })
      .sort(
        (a, b) =>
          (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4) ||
          b.confidence - a.confidence,
      );
  }, [findings, activeSeverities, search]);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold text-foreground">Findings</h1>
          {!isLoading && findings && (
            <span className="text-sm text-muted-foreground">({filtered.length})</span>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => setActiveSeverities(new Set())}
          className={cn(
            "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
            activeSeverities.size === 0
              ? "bg-primary/15 text-primary border-primary/40"
              : "bg-card text-muted-foreground border-border hover:text-foreground hover:border-foreground/30",
          )}
        >
          All
        </button>
        {SEVERITY_LEVELS.map((level) => (
          <button
            key={level}
            onClick={() => toggleSeverity(level)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs font-medium capitalize transition-colors",
              activeSeverities.has(level)
                ? (SEVERITY[level]?.badgeClass ?? SEVERITY.info!.badgeClass)
                : "bg-card text-muted-foreground border-border hover:text-foreground hover:border-foreground/30",
            )}
          >
            {level}
          </button>
        ))}

        <div className="relative ml-auto">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-8 w-64 rounded-md border border-input bg-background pl-8 pr-3 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border py-16 text-center">
          <AlertTriangle className="h-8 w-8 text-muted-foreground/50" />
          <p className="text-sm text-muted-foreground">
            No findings detected. Run a scan to discover attack paths.
          </p>
          <button
            onClick={() => navigate("/scans")}
            className="text-sm text-primary hover:underline"
          >
            Go to Scans
          </button>
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="px-4 py-2.5 text-left font-medium text-muted-foreground">Severity</th>
                <th className="px-4 py-2.5 text-left font-medium text-muted-foreground">Finding</th>
                <th className="px-4 py-2.5 text-left font-medium text-muted-foreground">Flow</th>
                <th className="px-4 py-2.5 text-left font-medium text-muted-foreground">Category</th>
                <th className="px-4 py-2.5 text-left font-medium text-muted-foreground">OWASP</th>
                <th className="px-4 py-2.5 text-right font-medium text-muted-foreground">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <FindingRow key={f.id} finding={f} onClick={() => navigate(`/findings/${f.id}`)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding: f, onClick }: { finding: Finding; onClick: () => void }) {
  return (
    <tr
      onClick={onClick}
      className="border-b border-border last:border-0 cursor-pointer transition-colors hover:bg-muted/40"
    >
      <td className="px-4 py-3">
        <Badge
          variant="outline"
          className={cn(
            "text-[10px] font-semibold uppercase",
            (SEVERITY[f.severity] ?? SEVERITY.low!).badgeClass,
          )}
        >
          {f.severity}
        </Badge>
      </td>
      <td className="px-4 py-3 max-w-xs">
        <p className="font-medium text-foreground truncate">{f.title}</p>
        <p className="text-xs text-muted-foreground truncate">{f.description}</p>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <MiniHexIcon kind={f.source_kind} />
          <span className="truncate max-w-[100px]">{f.source_name}</span>
          <ArrowRight className="h-3 w-3 shrink-0 text-muted-foreground/60" />
          <MiniHexIcon kind={f.target_kind} />
          <span className="truncate max-w-[100px]">{f.target_name}</span>
        </div>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-muted-foreground">{f.category}</span>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {(f.owasp_map ?? []).map((tag) => (
            <Badge key={tag} variant="secondary" className="text-[10px]">
              {tag}
            </Badge>
          ))}
        </div>
      </td>
      <td className="px-4 py-3 text-right">
        <span className="text-xs font-mono text-muted-foreground">
          {Math.round(f.confidence * 100)}%
        </span>
      </td>
    </tr>
  );
}

import { useState } from "react";
import { BookOpen, Play, ChevronDown, ChevronUp, Loader2 } from "lucide-react";
import { usePreBuiltQueries, useRunPreBuiltQuery } from "@entities/prebuilt";
import type { PreBuiltQuery } from "@entities/prebuilt";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { severityColor } from "@shared/theme/tokens";
import { QueryResult } from "./QueryResult";

const CATEGORY_ORDER = [
  "Critical Paths",
  "Vulnerabilities",
  "Supply Chain",
  "Chokepoints",
  "Combined",
];

function SevChip({ severity }: { severity: string }) {
  const color = severityColor(severity);
  return (
    <span
      className="inline-flex items-center gap-1 rounded-[2px] px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em]"
      style={{ backgroundColor: `${color}1A`, color, boxShadow: `inset 0 0 0 1px ${color}55` }}
    >
      <span className="h-1.5 w-1.5 rounded-[1px]" style={{ backgroundColor: color }} />
      {severity}
    </span>
  );
}

export function QueryLibrary() {
  const { data: queries, isLoading } = usePreBuiltQueries();

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [resultRows, setResultRows] = useState<Record<string, unknown>[]>([]);
  const [activeQuery, setActiveQuery] = useState<PreBuiltQuery | null>(null);

  const runQuery = useRunPreBuiltQuery();

  function handleToggle(query: PreBuiltQuery) {
    if (expandedId === query.id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(query.id);
    setResultRows([]);
    setActiveQuery(null);
    runQuery.mutate(query.id, {
      onSuccess: (data) => {
        setResultRows(data.rows);
        setActiveQuery(data.query);
      },
    });
  }

  const grouped = new Map<string, PreBuiltQuery[]>();
  for (const q of queries ?? []) {
    const list = grouped.get(q.category) ?? [];
    list.push(q);
    grouped.set(q.category, list);
  }

  const sortedCategories = CATEGORY_ORDER.filter((c) => grouped.has(c));
  for (const cat of grouped.keys()) {
    if (!sortedCategories.includes(cat)) sortedCategories.push(cat);
  }

  const total = queries?.length ?? 0;

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[1100px] space-y-4">
        <header className="min-w-0">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Graph Analysis <span className="text-primary/60">//</span> Query Library
          </p>
          <h1 className="mt-1.5 flex items-center gap-2.5 font-mono text-2xl font-bold uppercase tracking-[0.04em] text-foreground sm:text-[26px]">
            <span className="flex h-7 w-7 items-center justify-center rounded-[3px] bg-primary/10 ring-1 ring-inset ring-primary/30">
              <BookOpen className="h-4 w-4 text-primary" />
            </span>
            <span className="text-primary">▸</span>
            Query Library
            {total > 0 && (
              <span className="font-mono text-base font-semibold tabular-nums text-muted-foreground">
                {String(total).padStart(2, "0")}
              </span>
            )}
            <span className="blink-caret text-primary" aria-hidden>
              _
            </span>
          </h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Run curated detection queries against the graph and inspect the matched rows.
          </p>
        </header>

        {isLoading ? (
          <div className="space-y-4">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <Skeleton className="h-3 w-32 rounded-[2px]" />
                <Skeleton className="h-14 w-full rounded-[3px]" />
                <Skeleton className="h-14 w-full rounded-[3px]" />
              </div>
            ))}
          </div>
        ) : (
          <div className="space-y-6">
            {sortedCategories.map((category) => (
              <div key={category}>
                <div className="mb-2.5 flex items-center gap-2">
                  <span aria-hidden className="h-px w-6 bg-primary/50" />
                  <h3 className="font-mono text-console uppercase tracking-[0.18em] text-muted-foreground">
                    {category}
                  </h3>
                  <span aria-hidden className="h-px flex-1 bg-border/60" />
                  <span className="font-mono text-[10px] tabular-nums text-muted-foreground/70">
                    {String((grouped.get(category) ?? []).length).padStart(2, "0")}
                  </span>
                </div>
                <div className="space-y-2">
                  {(grouped.get(category) ?? []).map((query) => {
                    const isExpanded = expandedId === query.id;
                    const isRunning = runQuery.isPending && expandedId === query.id;
                    const color = severityColor(query.severity);

                    return (
                      <div
                        key={query.id}
                        className="card-elevated relative overflow-hidden rounded-md"
                      >
                        <span
                          aria-hidden
                          className="pointer-events-none absolute inset-y-0 left-0 w-0.5"
                          style={{ backgroundColor: color, opacity: 0.8 }}
                        />
                        <button
                          onClick={() => handleToggle(query)}
                          className="flex w-full items-center gap-3 px-3.5 py-3 text-left transition-colors hover:bg-white/[0.02]"
                        >
                          <Play className="h-3.5 w-3.5 flex-shrink-0 text-primary/70" />
                          <div className="min-w-0 flex-1">
                            <div className="mb-0.5 flex flex-wrap items-center gap-2">
                              <span className="text-sm font-medium text-foreground">{query.name}</span>
                              <SevChip severity={query.severity} />
                            </div>
                            <p className="truncate text-xs text-muted-foreground">
                              {query.description}
                            </p>
                            {((query.owasp_map?.length ?? 0) > 0 ||
                              (query.atlas_map?.length ?? 0) > 0) && (
                              <div className="mt-1 flex flex-wrap gap-1">
                                {query.owasp_map?.map((tag) => (
                                  <span
                                    key={tag}
                                    className="rounded-[2px] border border-border bg-black/40 px-1.5 py-0 font-mono text-[9px] uppercase tracking-[0.06em] text-primary/80"
                                  >
                                    {tag}
                                  </span>
                                ))}
                                {query.atlas_map?.map((tag) => (
                                  <span
                                    key={tag}
                                    className="rounded-[2px] border border-border bg-black/40 px-1.5 py-0 font-mono text-[9px] uppercase tracking-[0.06em] text-amber-400/90"
                                  >
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          {isExpanded ? (
                            <ChevronUp className="h-4 w-4 flex-shrink-0 text-primary" />
                          ) : (
                            <ChevronDown className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
                          )}
                        </button>

                        {isExpanded && (
                          <>
                            <div className="h-px bg-border/70" />
                            <div className="bg-black/20 px-3.5 py-3">
                              {isRunning ? (
                                <div className="flex items-center justify-center gap-2 py-4 font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
                                  <Loader2 className="h-4 w-4 animate-spin text-primary" />
                                  Running query…
                                </div>
                              ) : runQuery.isError && expandedId === query.id ? (
                                <div
                                  className="rounded-[3px] border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                                  style={{ boxShadow: "inset 2px 0 0 0 rgb(var(--tomato-9-raw))" }}
                                >
                                  {runQuery.error instanceof Error
                                    ? runQuery.error.message
                                    : "Query failed"}
                                </div>
                              ) : activeQuery ? (
                                <QueryResult rows={resultRows} query={activeQuery} />
                              ) : null}
                            </div>
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

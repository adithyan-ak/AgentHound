import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { BookOpen, Play, ChevronDown, ChevronUp, Loader2 } from "lucide-react";
import { fetchPreBuiltQueries, runPreBuiltQuery } from "@/api/analysis";
import type { PreBuiltQuery } from "@/api/types";
import { cn } from "@/lib/utils";
import { QueryResult } from "./QueryResult";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300",
  high: "bg-orange-900/40 text-orange-300",
  medium: "bg-yellow-900/40 text-yellow-300",
  low: "bg-blue-900/40 text-blue-300",
  info: "bg-zinc-700 text-zinc-300",
};

const CATEGORY_ORDER = [
  "Critical Paths",
  "Vulnerabilities",
  "Supply Chain",
  "Chokepoints",
  "Combined",
];

export function QueryLibrary() {
  const { data: queries, isLoading } = useQuery({
    queryKey: ["prebuilt-queries"],
    queryFn: fetchPreBuiltQueries,
    staleTime: 30_000,
  });

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [resultRows, setResultRows] = useState<Record<string, unknown>[]>([]);
  const [activeQuery, setActiveQuery] = useState<PreBuiltQuery | null>(null);

  const runQuery = useMutation({
    mutationFn: (id: string) => runPreBuiltQuery(id),
    onSuccess: (data) => {
      setResultRows(data.rows);
      setActiveQuery(data.query);
    },
  });

  function handleToggle(query: PreBuiltQuery) {
    if (expandedId === query.id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(query.id);
    setResultRows([]);
    setActiveQuery(null);
    runQuery.mutate(query.id);
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

  return (
    <div className="p-6">
      <h2 className="flex items-center gap-2 text-lg font-semibold text-zinc-100 mb-6">
        <BookOpen className="h-5 w-5 text-primary" />
        Query Library
      </h2>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-sm text-zinc-500 animate-pulse">
          Loading queries...
        </div>
      ) : (
        <div className="space-y-6">
          {sortedCategories.map((category) => (
            <div key={category}>
              <h3 className="text-xs font-medium text-zinc-400 uppercase tracking-wide mb-3">
                {category}
              </h3>
              <div className="space-y-2">
                {(grouped.get(category) ?? []).map((query) => {
                  const isExpanded = expandedId === query.id;
                  const isRunning =
                    runQuery.isPending && expandedId === query.id;

                  return (
                    <div
                      key={query.id}
                      className="rounded-lg border border-zinc-700 bg-zinc-800"
                    >
                      <button
                        onClick={() => handleToggle(query)}
                        className="flex w-full items-center gap-3 px-4 py-3 text-left"
                      >
                        <Play className="h-3.5 w-3.5 text-zinc-500 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="text-sm font-medium text-zinc-200">
                              {query.name}
                            </span>
                            <span
                              className={cn(
                                "inline-flex rounded-full px-1.5 py-0.5 text-[10px] font-medium",
                                SEVERITY_STYLES[query.severity] ??
                                  SEVERITY_STYLES.info,
                              )}
                            >
                              {query.severity}
                            </span>
                          </div>
                          <p className="text-xs text-zinc-500 truncate">
                            {query.description}
                          </p>
                          {query.owasp_map && query.owasp_map.length > 0 && (
                            <div className="flex gap-1 mt-1">
                              {query.owasp_map.map((tag) => (
                                <span
                                  key={tag}
                                  className="inline-flex rounded bg-zinc-700 px-1 py-0.5 text-[9px] font-mono text-zinc-400"
                                >
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        {isExpanded ? (
                          <ChevronUp className="h-4 w-4 text-zinc-500 flex-shrink-0" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-zinc-500 flex-shrink-0" />
                        )}
                      </button>

                      {isExpanded && (
                        <div className="border-t border-zinc-700 px-4 py-3">
                          {isRunning ? (
                            <div className="flex items-center justify-center gap-2 py-4 text-sm text-zinc-500">
                              <Loader2 className="h-4 w-4 animate-spin" />
                              Running query...
                            </div>
                          ) : runQuery.isError && expandedId === query.id ? (
                            <div className="rounded-md bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-300">
                              {runQuery.error instanceof Error
                                ? runQuery.error.message
                                : "Query failed"}
                            </div>
                          ) : activeQuery ? (
                            <QueryResult rows={resultRows} query={activeQuery} />
                          ) : null}
                        </div>
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
  );
}

import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { BookOpen, Play, ChevronDown, ChevronUp, Loader2 } from "lucide-react";
import { fetchPreBuiltQueries, runPreBuiltQuery } from "@/api/analysis";
import type { PreBuiltQuery } from "@/api/types";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { QueryResult } from "./QueryResult";

const SEVERITY_VARIANT: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
  critical: "destructive",
  high: "destructive",
  medium: "default",
  low: "secondary",
  info: "outline",
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
      <h2 className="flex items-center gap-2 text-lg font-semibold text-foreground mb-6">
        <BookOpen className="h-5 w-5 text-primary" />
        Query Library
      </h2>

      {isLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-6">
          {sortedCategories.map((category) => (
            <div key={category}>
              <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-3">
                {category}
              </h3>
              <div className="space-y-2">
                {(grouped.get(category) ?? []).map((query) => {
                  const isExpanded = expandedId === query.id;
                  const isRunning =
                    runQuery.isPending && expandedId === query.id;

                  return (
                    <Card key={query.id}>
                      <button
                        onClick={() => handleToggle(query)}
                        className="flex w-full items-center gap-3 px-4 py-3 text-left"
                      >
                        <Play className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="text-sm font-medium text-foreground">
                              {query.name}
                            </span>
                            <Badge
                              variant={SEVERITY_VARIANT[query.severity] ?? "outline"}
                              className="text-[10px] px-1.5 py-0"
                            >
                              {query.severity}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground truncate">
                            {query.description}
                          </p>
                          {query.owasp_map && query.owasp_map.length > 0 && (
                            <div className="flex gap-1 mt-1">
                              {query.owasp_map.map((tag) => (
                                <Badge
                                  key={tag}
                                  variant="secondary"
                                  className="rounded px-1 py-0 text-[9px] font-mono"
                                >
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                        {isExpanded ? (
                          <ChevronUp className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        )}
                      </button>

                      {isExpanded && (
                        <>
                          <Separator />
                          <CardContent className="px-4 py-3">
                            {isRunning ? (
                              <div className="flex items-center justify-center gap-2 py-4 text-sm text-muted-foreground">
                                <Loader2 className="h-4 w-4 animate-spin" />
                                Running query...
                              </div>
                            ) : runQuery.isError && expandedId === query.id ? (
                              <div className="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
                                {runQuery.error instanceof Error
                                  ? runQuery.error.message
                                  : "Query failed"}
                              </div>
                            ) : activeQuery ? (
                              <QueryResult rows={resultRows} query={activeQuery} />
                            ) : null}
                          </CardContent>
                        </>
                      )}
                    </Card>
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

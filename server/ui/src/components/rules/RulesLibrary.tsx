import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield } from "lucide-react";
import { fetchRules } from "@/api/rules";
import type { RuleInfo } from "@/api/rules";
import { Skeleton } from "@/components/ui/skeleton";
import { RuleCard } from "./RuleCard";
import { RuleFilters } from "./RuleFilters";

const TAG_ORDER = [
  "injection",
  "credential",
  "supply-chain",
  "sensitivity",
  "capability",
  "impersonation",
  "instruction-poisoning",
];

function groupByTag(rules: RuleInfo[]): Map<string, RuleInfo[]> {
  const grouped = new Map<string, RuleInfo[]>();
  for (const rule of rules) {
    const tag = rule.tags[0] ?? "other";
    const list = grouped.get(tag) ?? [];
    list.push(rule);
    grouped.set(tag, list);
  }
  return grouped;
}

export function RulesLibrary() {
  const [severity, setSeverity] = useState("all");
  const [collector, setCollector] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filterParams = useMemo(() => {
    const params: { severity?: string; collector?: string } = {};
    if (severity !== "all") params.severity = severity;
    if (collector !== "all") params.collector = collector;
    return params;
  }, [severity, collector]);

  const { data, isLoading } = useQuery({
    queryKey: ["rules", filterParams],
    queryFn: () => fetchRules(filterParams),
    staleTime: 30_000,
  });

  const grouped = useMemo(
    () => groupByTag(data?.rules ?? []),
    [data?.rules],
  );

  const sortedTags = useMemo(() => {
    const tags = TAG_ORDER.filter((t) => grouped.has(t));
    for (const t of grouped.keys()) {
      if (!tags.includes(t)) tags.push(t);
    }
    return tags;
  }, [grouped]);

  function handleClear() {
    setSeverity("all");
    setCollector("all");
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-foreground">
          <Shield className="h-5 w-5 text-primary" />
          Detection Rules
          {data && (
            <span className="text-sm font-normal text-muted-foreground">
              ({data.total})
            </span>
          )}
        </h2>
        <RuleFilters
          severity={severity}
          collector={collector}
          onSeverityChange={setSeverity}
          onCollectorChange={setCollector}
          onClear={handleClear}
        />
      </div>

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
      ) : data?.rules.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-sm text-muted-foreground">
          <Shield className="h-8 w-8 mb-2 opacity-40" />
          No rules match the selected filters.
        </div>
      ) : (
        <div className="space-y-6">
          {sortedTags.map((tag) => {
            const rules = grouped.get(tag) ?? [];
            return (
              <div key={tag}>
                <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-3">
                  {tag} ({rules.length})
                </h3>
                <div className="space-y-2">
                  {rules.map((rule) => (
                    <RuleCard
                      key={rule.id}
                      rule={rule}
                      isExpanded={expandedId === rule.id}
                      onToggle={() =>
                        setExpandedId(
                          expandedId === rule.id ? null : rule.id,
                        )
                      }
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

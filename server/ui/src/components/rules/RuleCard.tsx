import { ChevronDown, ChevronUp } from "lucide-react";
import type { RuleInfo } from "@/api/rules";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Separator } from "@/components/ui/separator";
import { RuleDetail } from "./RuleDetail";

const COLLECTOR_CLASS: Record<string, string> = {
  mcp: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  a2a: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  config: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  all: "bg-slate-500/10 text-slate-400 border-slate-500/30",
};

const SOURCE_CLASS: Record<string, string> = {
  builtin: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  custom: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
};

interface RuleCardProps {
  rule: RuleInfo;
  isExpanded: boolean;
  onToggle: () => void;
}

export function RuleCard({ rule, isExpanded, onToggle }: RuleCardProps) {
  return (
    <Card>
      <button
        onClick={onToggle}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-sm font-medium text-foreground">
              {rule.name}
            </span>
            <SeverityBadge severity={rule.severity} />
            <Badge
              className={`rounded px-1.5 py-0 text-[10px] border ${COLLECTOR_CLASS[rule.collector] ?? COLLECTOR_CLASS.all}`}
            >
              {rule.collector}
            </Badge>
            <Badge
              className={`rounded px-1.5 py-0 text-[10px] border ${SOURCE_CLASS[rule.source] ?? SOURCE_CLASS.builtin}`}
            >
              {rule.source}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground truncate">
            {rule.description}
          </p>
          <div className="flex flex-wrap gap-1 mt-1">
            {rule.targets.map((t) => (
              <Badge
                key={t}
                variant="outline"
                className="rounded px-1 py-0 text-[9px] font-mono"
              >
                {t}
              </Badge>
            ))}
            {rule.owasp?.map((tag) => (
              <Badge
                key={tag}
                variant="secondary"
                className="rounded px-1 py-0 text-[9px] font-mono"
              >
                {tag}
              </Badge>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {rule.test_count > 0 && (
            <span className="text-[10px] text-muted-foreground">
              {rule.test_count} tests
            </span>
          )}
          {isExpanded ? (
            <ChevronUp className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </button>

      {isExpanded && (
        <>
          <Separator />
          <CardContent className="px-4 py-3">
            <RuleDetail ruleId={rule.id} />
          </CardContent>
        </>
      )}
    </Card>
  );
}

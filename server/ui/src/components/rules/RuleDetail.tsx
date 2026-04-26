import { useQuery } from "@tanstack/react-query";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import { fetchRuleDetail } from "@/api/rules";
import type { MatcherSpec, TestCase } from "@/api/rules";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface RuleDetailProps {
  ruleId: string;
}

function MatcherDisplay({ matcher }: { matcher: MatcherSpec }) {
  switch (matcher.Type) {
    case "regex":
      return (
        <div className="space-y-2">
          <div className="text-xs text-muted-foreground font-medium">
            Pattern {matcher.CaseInsensitive && "(case-insensitive)"}
          </div>
          <code className="block rounded-md bg-muted px-3 py-2 text-xs font-mono break-all">
            {matcher.Pattern}
          </code>
        </div>
      );

    case "keyword":
      return (
        <div className="space-y-2">
          <div className="text-xs text-muted-foreground font-medium">
            Keywords
            {matcher.CaseInsensitive && " (case-insensitive)"}
            {matcher.MatchMode && ` - match ${matcher.MatchMode}`}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {matcher.Keywords?.map((kw) => (
              <Badge
                key={kw}
                variant="secondary"
                className="rounded px-1.5 py-0.5 text-[11px] font-mono"
              >
                {kw}
              </Badge>
            ))}
          </div>
        </div>
      );

    case "prefix":
      return (
        <div className="space-y-2">
          <div className="text-xs text-muted-foreground font-medium">
            Prefixes {matcher.CaseInsensitive && "(case-insensitive)"}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {matcher.Prefixes?.map((p) => (
              <Badge
                key={p}
                variant="secondary"
                className="rounded px-1.5 py-0.5 text-[11px] font-mono"
              >
                {p}
              </Badge>
            ))}
          </div>
        </div>
      );

    case "entropy":
      return (
        <div className="space-y-2">
          <div className="text-xs text-muted-foreground font-medium">
            Entropy Check
          </div>
          <div className="flex gap-4 text-xs">
            <span>
              <span className="text-muted-foreground">Charset:</span>{" "}
              <span className="font-mono">{matcher.Charset}</span>
            </span>
            <span>
              <span className="text-muted-foreground">Threshold:</span>{" "}
              <span className="font-mono">{matcher.Threshold}</span>
            </span>
            {matcher.MinLength != null && matcher.MinLength > 0 && (
              <span>
                <span className="text-muted-foreground">Min length:</span>{" "}
                <span className="font-mono">{matcher.MinLength}</span>
              </span>
            )}
          </div>
        </div>
      );

    case "compound":
      return (
        <div className="space-y-3">
          <div className="text-xs text-muted-foreground font-medium">
            Compound ({matcher.Operator?.toUpperCase()})
          </div>
          <div className="space-y-2 pl-3 border-l-2 border-muted">
            {matcher.Matchers?.map((sub, i) => (
              <MatcherDisplay key={i} matcher={sub} />
            ))}
          </div>
        </div>
      );

    default:
      return (
        <div className="text-xs text-muted-foreground">
          Unknown matcher type: {matcher.Type}
        </div>
      );
  }
}

function TestCasesTable({ tests }: { tests: TestCase[] }) {
  if (tests.length === 0) return null;

  return (
    <div className="space-y-2">
      <div className="text-xs text-muted-foreground font-medium">
        Test Cases ({tests.length})
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="h-8 text-xs">Input</TableHead>
            <TableHead className="h-8 text-xs w-[80px]">Expected</TableHead>
            <TableHead className="h-8 text-xs">Description</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {tests.map((tc, i) => (
            <TableRow key={i}>
              <TableCell className="py-1.5">
                <code className="text-[11px] font-mono break-all">
                  {tc.Input}
                </code>
              </TableCell>
              <TableCell className="py-1.5">
                {tc.ShouldMatch ? (
                  <span className="inline-flex items-center gap-1 text-xs text-green-400">
                    <CheckCircle2 className="h-3 w-3" />
                    Match
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                    <XCircle className="h-3 w-3" />
                    No match
                  </span>
                )}
              </TableCell>
              <TableCell className="py-1.5 text-xs text-muted-foreground">
                {tc.Description}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export function RuleDetail({ ruleId }: RuleDetailProps) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["rule-detail", ruleId],
    queryFn: () => fetchRuleDetail(ruleId),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center gap-2 py-4 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading rule details...
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {error instanceof Error ? error.message : "Failed to load rule"}
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">{data.description}</p>
      <Separator />
      <MatcherDisplay matcher={data.matcher} />
      {data.tests.length > 0 && (
        <>
          <Separator />
          <TestCasesTable tests={data.tests} />
        </>
      )}
    </div>
  );
}

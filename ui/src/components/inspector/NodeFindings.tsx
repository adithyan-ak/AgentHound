import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import { fetchFindings } from "@/api/analysis";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface NodeFindingsProps {
  nodeId: string;
}

const SEVERITY_BADGE_VARIANT: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
  critical: "destructive",
  high: "destructive",
  medium: "default",
  low: "secondary",
  info: "outline",
};

const SEVERITY_CARD_STYLES: Record<string, string> = {
  critical: "border-red-800 bg-red-900/40",
  high: "border-orange-800 bg-orange-900/40",
  medium: "border-yellow-800 bg-yellow-900/40",
  low: "border-blue-800 bg-blue-900/40",
  info: "border-border bg-muted/40",
};

export function NodeFindings({ nodeId }: NodeFindingsProps) {
  const { data: allFindings, isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="py-4 text-sm text-muted-foreground text-center">Loading...</div>
    );
  }

  const findings = (allFindings ?? []).filter(
    (f) => f.source_id === nodeId || f.target_id === nodeId,
  );

  if (findings.length === 0) {
    return (
      <div className="py-4 text-sm text-muted-foreground text-center">
        No findings for this node
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {findings.map((finding) => (
        <Card
          key={finding.id}
          className={SEVERITY_CARD_STYLES[finding.severity] ?? SEVERITY_CARD_STYLES.info}
        >
          <CardContent className="px-3 py-2">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <Badge variant={SEVERITY_BADGE_VARIANT[finding.severity] ?? "outline"} className="text-[10px] uppercase">
                    {finding.severity}
                  </Badge>
                  <span className="text-xs font-medium">{finding.title}</span>
                </div>
                <p className="text-xs opacity-80">{finding.description}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

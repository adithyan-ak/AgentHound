import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import { fetchFindings } from "@/api/analysis";
import { cn } from "@/lib/utils";

interface NodeFindingsProps {
  nodeId: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-800",
  high: "bg-orange-900/40 text-orange-300 border-orange-800",
  medium: "bg-yellow-900/40 text-yellow-300 border-yellow-800",
  low: "bg-blue-900/40 text-blue-300 border-blue-800",
  info: "bg-zinc-700/40 text-zinc-300 border-zinc-600",
};

export function NodeFindings({ nodeId }: NodeFindingsProps) {
  const { data: allFindings, isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="py-4 text-sm text-zinc-500 text-center">Loading...</div>
    );
  }

  const findings = (allFindings ?? []).filter(
    (f) => f.source_id === nodeId || f.target_id === nodeId,
  );

  if (findings.length === 0) {
    return (
      <div className="py-4 text-sm text-zinc-500 text-center">
        No findings for this node
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {findings.map((finding) => (
        <div
          key={finding.id}
          className={cn(
            "rounded-md border px-3 py-2",
            SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info,
          )}
        >
          <div className="flex items-start gap-2">
            <AlertTriangle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-xs font-medium uppercase">
                  {finding.severity}
                </span>
                <span className="text-xs font-medium">{finding.title}</span>
              </div>
              <p className="text-xs opacity-80">{finding.description}</p>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

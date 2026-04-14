import { useQuery } from "@tanstack/react-query";
import { KeyRound, AlertTriangle, Lock, Package, CheckCircle2 } from "lucide-react";
import { fetchNodes } from "@/api/graph";
import { cn } from "@/lib/utils";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { InfoTip } from "./InfoTip";

interface MetricRow {
  icon: React.ReactNode;
  label: string;
  count: number;
  severity: string;
}

export function CredentialExposure() {
  const { data: credentials, isLoading: loadingCreds } = useQuery({
    queryKey: ["dashboard", "credential-exposure-creds"],
    queryFn: () => fetchNodes("Credential", 10000),
    staleTime: 30_000,
  });

  const { data: servers, isLoading: loadingServers } = useQuery({
    queryKey: ["dashboard", "credential-exposure-servers"],
    queryFn: () => fetchNodes("MCPServer", 10000),
    staleTime: 30_000,
  });

  const isLoading = loadingCreds || loadingServers;

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1.5 text-sm font-medium">
            Credential Exposure
            <InfoTip text="Counts of hardcoded credentials, high-entropy secrets (likely API keys), and unpinned MCP server packages in your configs." />
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-28 w-full" />
        </CardContent>
      </Card>
    );
  }

  const hardcoded = (credentials ?? []).filter(
    (c) => String(c.properties.type) === "hardcoded" || c.properties.is_exposed === true,
  ).length;

  const highEntropy = (credentials ?? []).filter(
    (c) => c.properties.high_entropy === true,
  ).length;

  const unpinned = (servers ?? []).filter(
    (s) => s.properties.is_pinned === false,
  ).length;

  const allClear = hardcoded === 0 && highEntropy === 0 && unpinned === 0;

  const rows: MetricRow[] = [
    {
      icon: <AlertTriangle className="h-4 w-4 text-red-400" />,
      label: "Hardcoded / Exposed",
      count: hardcoded,
      severity: "critical",
    },
    {
      icon: <Lock className="h-4 w-4 text-orange-400" />,
      label: "High-Entropy Secrets",
      count: highEntropy,
      severity: "high",
    },
    {
      icon: <Package className="h-4 w-4 text-yellow-400" />,
      label: "Unpinned Packages",
      count: unpinned,
      severity: "medium",
    },
  ];

  const SEVERITY_STYLE: Record<string, string> = {
    critical: "bg-red-900/60 text-red-300 border-red-700",
    high: "bg-orange-900/60 text-orange-300 border-orange-700",
    medium: "bg-yellow-900/60 text-yellow-300 border-yellow-700",
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <KeyRound className="h-4 w-4 text-muted-foreground" />
          Credential Exposure
        </CardTitle>
      </CardHeader>
      <CardContent>
        {allClear ? (
          <div className="flex items-center gap-3 py-4">
            <CheckCircle2 className="h-8 w-8 text-green-500" />
            <div>
              <p className="text-sm font-medium text-foreground">All Clear</p>
              <p className="text-xs text-muted-foreground">
                No exposed credentials or unpinned packages detected
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {rows.map((row) => (
              <div key={row.label} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {row.icon}
                  <span className="text-sm text-muted-foreground">{row.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "font-mono text-lg font-semibold",
                      row.count > 0 ? "text-red-400" : "text-green-400",
                    )}
                  >
                    {row.count}
                  </span>
                  <Badge
                    variant="outline"
                    className={cn(
                      "text-[10px] font-semibold uppercase",
                      row.count > 0
                        ? SEVERITY_STYLE[row.severity]
                        : "bg-muted text-muted-foreground border-border",
                    )}
                  >
                    {row.count > 0 ? row.severity : "ok"}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

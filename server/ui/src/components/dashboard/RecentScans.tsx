import { useQuery } from "@tanstack/react-query";
import { fetchScans } from "@/api/scans";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { InfoTip } from "./InfoTip";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { FEEDBACK } from "@/theme/tokens";

interface StatusStyle {
  bg: string;
  text: string;
}

const STATUS_STYLE: Record<string, StatusStyle> = {
  completed: { bg: FEEDBACK.success.bg, text: FEEDBACK.success.text },
  running: { bg: FEEDBACK.warning.bg, text: FEEDBACK.warning.text },
  failed: { bg: FEEDBACK.error.bg, text: FEEDBACK.error.text },
  pending: { bg: "transparent", text: "" },
};

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function RecentScans() {
  const { data: scans, isLoading } = useQuery({
    queryKey: ["dashboard", "recent-scans"],
    queryFn: () => fetchScans(5, 0),
    staleTime: 30_000,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-sm font-medium">
          Recent Scans
          <InfoTip text="Last 5 scan runs showing collector type, status, and how many nodes and edges were discovered. Run 'agenthound scan' to trigger a new scan." />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : !scans || scans.length === 0 ? (
          <div className="flex h-48 items-center justify-center text-muted-foreground">No scans yet</div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Collector</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Nodes</TableHead>
                <TableHead>Edges</TableHead>
                <TableHead>When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell className="text-foreground">{scan.collector}</TableCell>
                  <TableCell>
                    {(() => {
                      const style = STATUS_STYLE[scan.status] ?? STATUS_STYLE.pending!;
                      return (
                        <Badge
                          variant="outline"
                          className="text-[10px] font-semibold uppercase"
                          style={style.text ? { backgroundColor: style.bg, color: style.text } : undefined}
                        >
                          {scan.status}
                        </Badge>
                      );
                    })()}
                  </TableCell>
                  <TableCell className="font-mono text-muted-foreground">{scan.node_count}</TableCell>
                  <TableCell className="font-mono text-muted-foreground">{scan.edge_count}</TableCell>
                  <TableCell className="text-muted-foreground">{timeAgo(scan.started_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

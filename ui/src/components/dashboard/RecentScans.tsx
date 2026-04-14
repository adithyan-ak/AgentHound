import { useQuery } from "@tanstack/react-query";
import { fetchScans } from "@/api/scans";
import { cn } from "@/lib/utils";
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

const STATUS_STYLE: Record<string, string> = {
  completed: "bg-green-900/60 text-green-300",
  running: "bg-yellow-900/60 text-yellow-300",
  failed: "bg-red-900/60 text-red-300",
  pending: "bg-muted text-muted-foreground",
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
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[10px] font-semibold uppercase",
                        STATUS_STYLE[scan.status] ?? STATUS_STYLE.pending,
                      )}
                    >
                      {scan.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{scan.node_count}</TableCell>
                  <TableCell className="text-muted-foreground">{scan.edge_count}</TableCell>
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

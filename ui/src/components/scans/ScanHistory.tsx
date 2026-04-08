import type { Scan } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";

interface ScanHistoryProps {
  scans: Scan[];
}

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  completed: "default",
  running: "secondary",
  pending: "outline",
  failed: "destructive",
};

const COLLECTOR_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  config: "secondary",
  mcp: "default",
  a2a: "outline",
};

function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return "-";
  return new Date(dateStr).toLocaleString();
}

export function ScanHistory({ scans }: ScanHistoryProps) {
  if (scans.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
        No scans recorded yet
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="text-xs">ID</TableHead>
            <TableHead className="text-xs">Collector</TableHead>
            <TableHead className="text-xs">Status</TableHead>
            <TableHead className="text-xs">Started</TableHead>
            <TableHead className="text-xs">Completed</TableHead>
            <TableHead className="text-xs text-right">Nodes</TableHead>
            <TableHead className="text-xs text-right">Edges</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {scans.map((scan) => (
            <TableRow key={scan.id}>
              <TableCell className="font-mono text-xs">
                {scan.id.slice(0, 8)}
              </TableCell>
              <TableCell>
                <Badge variant={COLLECTOR_VARIANT[scan.collector] ?? "secondary"} className="text-[10px]">
                  {scan.collector}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge variant={STATUS_VARIANT[scan.status] ?? "secondary"} className="text-[10px]">
                  {scan.status}
                </Badge>
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {formatDate(scan.started_at)}
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {formatDate(scan.completed_at)}
              </TableCell>
              <TableCell className="text-xs text-right">
                {scan.node_count}
              </TableCell>
              <TableCell className="text-xs text-right">
                {scan.edge_count}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

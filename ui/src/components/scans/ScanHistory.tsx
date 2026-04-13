import { useState } from "react";
import { Trash2 } from "lucide-react";
import type { Scan } from "@/api/types";
import { deleteScan } from "@/api/scans";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
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
  onDeleted?: () => void;
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

export function ScanHistory({ scans, onDeleted }: ScanHistoryProps) {
  const [confirmScan, setConfirmScan] = useState<Scan | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function handleConfirmedDelete() {
    if (!confirmScan) return;
    setDeleting(true);
    try {
      await deleteScan(confirmScan.id);
      setConfirmScan(null);
      onDeleted?.();
    } finally {
      setDeleting(false);
    }
  }

  if (scans.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
        No scans recorded yet
      </div>
    );
  }

  return (
    <>
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
              <TableHead className="text-xs w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan) => (
              <TableRow key={`${scan.id}-${scan.collector}`}>
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
                <TableCell>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-muted-foreground hover:text-destructive"
                    onClick={() => setConfirmScan(scan)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog open={!!confirmScan} onOpenChange={(v) => !v && setConfirmScan(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete scan?</DialogTitle>
            <DialogDescription>
              This will permanently delete the scan record and remove all
              {confirmScan ? ` ${confirmScan.node_count} nodes and ${confirmScan.edge_count} edges` : ""}{" "}
              it contributed to the graph. Nodes shared with other scans will be preserved.
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2 mt-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmScan(null)}
              disabled={deleting}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleConfirmedDelete}
              disabled={deleting}
            >
              {deleting ? "Deleting..." : "Delete scan"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

import type { Scan } from "@/api/types";
import { cn } from "@/lib/utils";

interface ScanHistoryProps {
  scans: Scan[];
}

const STATUS_STYLES: Record<string, string> = {
  completed: "bg-green-900/40 text-green-300",
  running: "bg-blue-900/40 text-blue-300",
  pending: "bg-yellow-900/40 text-yellow-300",
  failed: "bg-red-900/40 text-red-300",
};

const COLLECTOR_STYLES: Record<string, string> = {
  config: "bg-zinc-700 text-zinc-300",
  mcp: "bg-emerald-900/40 text-emerald-300",
  a2a: "bg-purple-900/40 text-purple-300",
};

function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return "-";
  return new Date(dateStr).toLocaleString();
}

export function ScanHistory({ scans }: ScanHistoryProps) {
  if (scans.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-zinc-500">
        No scans recorded yet
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-700 text-left">
            <th className="px-3 py-2 text-xs font-medium text-zinc-400">ID</th>
            <th className="px-3 py-2 text-xs font-medium text-zinc-400">Collector</th>
            <th className="px-3 py-2 text-xs font-medium text-zinc-400">Status</th>
            <th className="px-3 py-2 text-xs font-medium text-zinc-400">Started</th>
            <th className="px-3 py-2 text-xs font-medium text-zinc-400">Completed</th>
            <th className="px-3 py-2 text-xs font-medium text-zinc-400 text-right">Nodes</th>
            <th className="px-3 py-2 text-xs font-medium text-zinc-400 text-right">Edges</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-700/50">
          {scans.map((scan) => (
            <tr key={scan.id} className="hover:bg-zinc-800/50">
              <td className="px-3 py-2 font-mono text-xs text-zinc-300">
                {scan.id.slice(0, 8)}
              </td>
              <td className="px-3 py-2">
                <span
                  className={cn(
                    "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium",
                    COLLECTOR_STYLES[scan.collector] ?? "bg-zinc-700 text-zinc-300",
                  )}
                >
                  {scan.collector}
                </span>
              </td>
              <td className="px-3 py-2">
                <span
                  className={cn(
                    "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium",
                    STATUS_STYLES[scan.status] ?? "bg-zinc-700 text-zinc-300",
                  )}
                >
                  {scan.status}
                </span>
              </td>
              <td className="px-3 py-2 text-xs text-zinc-400">
                {formatDate(scan.started_at)}
              </td>
              <td className="px-3 py-2 text-xs text-zinc-400">
                {formatDate(scan.completed_at)}
              </td>
              <td className="px-3 py-2 text-xs text-zinc-300 text-right">
                {scan.node_count}
              </td>
              <td className="px-3 py-2 text-xs text-zinc-300 text-right">
                {scan.edge_count}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

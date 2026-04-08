import { useQuery } from "@tanstack/react-query";
import { fetchScans } from "@/api/scans";
import { cn } from "@/lib/utils";

const STATUS_STYLE: Record<string, string> = {
  completed: "bg-green-900/60 text-green-300",
  running: "bg-yellow-900/60 text-yellow-300",
  failed: "bg-red-900/60 text-red-300",
  pending: "bg-zinc-700 text-zinc-400",
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
    <div className="rounded-lg border border-zinc-700 bg-zinc-800 p-4">
      <h3 className="mb-4 text-sm font-medium text-zinc-300">Recent Scans</h3>
      {isLoading ? (
        <div className="flex h-48 items-center justify-center text-zinc-500">Loading...</div>
      ) : !scans || scans.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-zinc-500">No scans yet</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-zinc-700 text-xs text-zinc-500">
                <th className="pb-2 pr-4 font-medium">Collector</th>
                <th className="pb-2 pr-4 font-medium">Status</th>
                <th className="pb-2 pr-4 font-medium">Nodes</th>
                <th className="pb-2 pr-4 font-medium">Edges</th>
                <th className="pb-2 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className="border-b border-zinc-700/50 last:border-0">
                  <td className="py-2 pr-4 text-zinc-200">{scan.collector}</td>
                  <td className="py-2 pr-4">
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                        STATUS_STYLE[scan.status] ?? STATUS_STYLE.pending,
                      )}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-zinc-400">{scan.node_count}</td>
                  <td className="py-2 pr-4 text-zinc-400">{scan.edge_count}</td>
                  <td className="py-2 text-zinc-500">{timeAgo(scan.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

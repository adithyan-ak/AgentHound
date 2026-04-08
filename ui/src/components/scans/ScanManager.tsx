import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ScanSearch, Plus } from "lucide-react";
import { fetchScans } from "@/api/scans";
import { ScanHistory } from "./ScanHistory";
import { NewScan } from "./NewScan";

export function ScanManager() {
  const [showNewScan, setShowNewScan] = useState(false);

  const { data: scans, isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => fetchScans(),
    staleTime: 30_000,
  });

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
          <ScanSearch className="h-5 w-5 text-primary" />
          Scan Manager
        </h2>
        <button
          onClick={() => setShowNewScan(true)}
          className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </button>
      </div>

      <div className="rounded-lg border border-zinc-700 bg-zinc-800">
        {isLoading ? (
          <div className="flex items-center justify-center py-12 text-sm text-zinc-500 animate-pulse">
            Loading scan history...
          </div>
        ) : (
          <ScanHistory scans={scans ?? []} />
        )}
      </div>

      <NewScan open={showNewScan} onClose={() => setShowNewScan(false)} />
    </div>
  );
}

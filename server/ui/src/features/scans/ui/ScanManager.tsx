import { useState } from "react";
import { ScanSearch, Plus, Upload } from "lucide-react";
import { useScans, SCANS_LIST_LIMIT } from "@entities/scan";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { WidgetCard } from "@shared/ui/widgets";
import { ScanHistory } from "./ScanHistory";
import { NewScan } from "./NewScan";
import { ScanImport } from "./ScanImport";

const ghostBtn =
  "inline-flex h-8 items-center gap-1.5 rounded-[3px] border border-border bg-black/30 px-2.5 font-mono text-[11px] uppercase tracking-[0.08em] text-foreground/80 transition-colors hover:border-primary/50 hover:bg-primary/10 hover:text-primary";
const primaryBtn =
  "inline-flex h-8 items-center gap-1.5 rounded-[3px] bg-primary px-3 font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-primary-foreground transition-colors hover:bg-primary/90";

export function ScanManager() {
  const [showNewScan, setShowNewScan] = useState(false);
  const [showImport, setShowImport] = useState(false);

  // Scan-manager list. The page size grows on demand: a full page implies more
  // rows may exist server-side (the list endpoint is offset/limit paginated),
  // so "Load more" fetches a larger window. Upload/delete mutations invalidate
  // the ["scans"] prefix, so the list refreshes automatically after a write.
  const [limit, setLimit] = useState(SCANS_LIST_LIMIT);
  const { data: scans, isLoading, isFetching } = useScans(limit);

  const total = scans?.length ?? 0;
  // A page filled to the requested limit signals there may be more rows.
  const canLoadMore = total === limit;

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[1600px] space-y-3">
        <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              Data Collection <span className="text-primary/60">//</span> Scan Operations
            </p>
            <h1 className="mt-1.5 flex items-center gap-2.5 font-mono text-2xl font-bold uppercase tracking-[0.04em] text-foreground sm:text-[26px]">
              <span className="flex h-7 w-7 items-center justify-center rounded-[3px] bg-primary/10 ring-1 ring-inset ring-primary/30">
                <ScanSearch className="h-4 w-4 text-primary" />
              </span>
              <span className="text-primary">▸</span>
              Scan Manager
              {total > 0 && (
                <span className="font-mono text-base font-semibold tabular-nums text-muted-foreground">
                  {String(total).padStart(2, "0")}
                </span>
              )}
              <span className="blink-caret text-primary" aria-hidden>
                _
              </span>
            </h1>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Trigger collectors from the CLI and review the ingest history.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button className={ghostBtn} onClick={() => setShowImport(true)}>
              <Upload className="h-3.5 w-3.5" /> Import scan
            </button>
            <button className={primaryBtn} onClick={() => setShowNewScan(true)}>
              <Plus className="h-3.5 w-3.5" /> New Scan
            </button>
          </div>
        </header>

        <WidgetCard title="Ingest Log" icon={ScanSearch} flush>
          {isLoading ? (
            <div className="space-y-2 p-3">
              <Skeleton className="h-10 w-full rounded-[2px]" />
              <Skeleton className="h-10 w-full rounded-[2px]" />
              <Skeleton className="h-10 w-3/4 rounded-[2px]" />
            </div>
          ) : (
            <ScanHistory scans={scans ?? []} />
          )}
        </WidgetCard>

        {canLoadMore && (
          <div className="flex justify-center">
            <button
              className={ghostBtn}
              disabled={isFetching}
              onClick={() => setLimit((l) => l + SCANS_LIST_LIMIT)}
            >
              {isFetching ? "Loading…" : "Load more"}
            </button>
          </div>
        )}

        <NewScan open={showNewScan} onClose={() => setShowNewScan(false)} />
        <ScanImport open={showImport} onClose={() => setShowImport(false)} />
      </div>
    </div>
  );
}

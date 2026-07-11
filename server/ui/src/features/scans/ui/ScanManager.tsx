import { useState } from "react";
import { ScanSearch, Plus, Upload } from "lucide-react";
import { SCANS_LIST_LIMIT, useScanPage } from "@entities/scan";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { WidgetCard } from "@shared/ui/widgets";
import { DataStateNotice } from "@shared/ui/feedback";
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
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState<string>();

  const {
    data: page,
    isLoading,
    isError,
    error,
    dataUpdatedAt,
  } = useScanPage(
    SCANS_LIST_LIMIT,
    offset,
    revision,
  );
  const scans = page?.scans;
  const loaded = scans?.length ?? 0;
  const total = page?.total ?? loaded;
  const coldError = isError && page === undefined;
  const cachedError = isError && page !== undefined;
  const limited = offset > 0 || total > loaded || page?.hasMore === true;
  const rangeStart = loaded > 0 ? offset + 1 : 0;
  const rangeEnd = offset + loaded;
  const canGoBack = offset > 0;
  const canGoForward =
    page?.hasMore === true &&
    page.revision != null &&
    !page.revisionConflict;

  function showPreviousPage() {
    const previousOffset = Math.max(0, offset - SCANS_LIST_LIMIT);
    setOffset(previousOffset);
  }

  function showNextPage() {
    if (!canGoForward || !page?.revision) return;
    setRevision(page.revision);
    setOffset(offset + SCANS_LIST_LIMIT);
  }

  function restartPagination() {
    setRevision(page?.revision ?? undefined);
    setOffset(0);
  }

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

        {cachedError && (
          <DataStateNotice tone="warning" title="Showing cached scan history">
            The refresh failed. Rows are from{" "}
            {new Date(dataUpdatedAt).toLocaleString()} and may be stale.
          </DataStateNotice>
        )}
        {page && !page.revisionConflict && page.revision == null && (
          <DataStateNotice tone="warning" title="Scan history page incomplete">
            Pagination metadata was unavailable. The {loaded} loaded rows are
            not a complete history total.
          </DataStateNotice>
        )}
        {page?.revisionConflict && (
          <DataStateNotice tone="warning" title="Scan history changed">
            The scan history changed while paging. Restart from the newest page
            to avoid mixing revisions.
          </DataStateNotice>
        )}

        <WidgetCard title="Ingest Log" icon={ScanSearch} flush>
          {isLoading ? (
            <div className="space-y-2 p-3">
              <Skeleton className="h-10 w-full rounded-[2px]" />
              <Skeleton className="h-10 w-full rounded-[2px]" />
              <Skeleton className="h-10 w-3/4 rounded-[2px]" />
            </div>
          ) : coldError ? (
            <div className="p-3">
              <DataStateNotice tone="error" title="Scan history unavailable">
                {error instanceof Error
                  ? error.message
                  : "The scan history request failed."}
              </DataStateNotice>
            </div>
          ) : page?.revisionConflict ? (
            <div className="flex items-center justify-between gap-3 p-3">
              <span className="text-sm text-muted-foreground">
                This page belongs to an older scan-history revision.
              </span>
              <button className={ghostBtn} onClick={restartPagination}>
                Restart pagination
              </button>
            </div>
          ) : (
            <>
              {limited && (
                <div className="border-b border-border/70 px-3 py-2 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  Showing scans {rangeStart}–{rangeEnd} of {total} (newest
                  first; page size {SCANS_LIST_LIMIT})
                </div>
              )}
              <ScanHistory scans={scans ?? []} />
              {(canGoBack || canGoForward) && (
                <nav
                  aria-label="Scan history pagination"
                  className="flex items-center justify-between border-t border-border/70 px-3 py-2"
                >
                  <button
                    className={ghostBtn}
                    onClick={showPreviousPage}
                    disabled={!canGoBack}
                  >
                    Previous
                  </button>
                  <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                    {rangeStart}–{rangeEnd} of {total}
                  </span>
                  <button
                    className={ghostBtn}
                    onClick={showNextPage}
                    disabled={!canGoForward}
                  >
                    Next
                  </button>
                </nav>
              )}
            </>
          )}
        </WidgetCard>

        <NewScan open={showNewScan} onClose={() => setShowNewScan(false)} />
        <ScanImport open={showImport} onClose={() => setShowImport(false)} />
      </div>
    </div>
  );
}

import { Link } from "react-router-dom";
import { AlertCircle, ScanSearch, ArrowRight } from "lucide-react";
import { useGraphStats } from "@entities/graph-stats";
import { useFindings } from "@entities/finding";
import { useNodes } from "@entities/node";
import {
  latestPublishedScan,
  useLatestPublishedScan,
  useScans,
} from "@entities/scan";
import { useProjectionState } from "@entities/posture";
import { AsyncBoundary, DataStateNotice } from "@shared/ui/feedback";
import { sameDashboardProjection } from "../model/projection";
import { DashboardHeader } from "./DashboardHeader";
import { StatCards } from "./StatCards";
import { ExposureGauge } from "./ExposureGauge";
import { SeverityRings } from "./SeverityRings";
import { CategoryBreakdown } from "./CategoryBreakdown";
import { AuthCoverage } from "./AuthCoverage";
import { InventoryTrend } from "./InventoryTrend";
import { TopRiskyEntities } from "./TopRiskyEntities";
import { TopFindings } from "./TopFindings";
import { CrossProtocol } from "./CrossProtocol";
import { Chokepoints } from "./Chokepoints";
import { RecentScans } from "./RecentScans";

function EmptyState() {
  return (
    <div className="card-elevated relative mt-4 flex flex-col items-center justify-center gap-4 overflow-hidden rounded-md px-6 py-16 text-center">
      <span aria-hidden className="absolute left-0 top-0 h-px w-16 bg-primary/80" />
      <div className="flex h-12 w-12 items-center justify-center rounded-[4px] bg-primary/10 ring-1 ring-inset ring-primary/30">
        <ScanSearch className="h-6 w-6 text-primary" />
      </div>
      <div className="space-y-1.5">
        <h2 className="font-mono text-base font-semibold uppercase tracking-[0.08em] text-foreground">
          No attack surface mapped
        </h2>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">
          Run a scan to discover your agent, MCP, and A2A infrastructure. Once ingested, your
          exposure index, findings, and attack paths will appear here.
        </p>
      </div>
      <code className="rounded-[3px] border border-border bg-black/50 px-3 py-1.5 font-mono text-sm text-primary">
        <span className="text-muted-foreground">$</span> agenthound scan
      </code>
      <Link
        to="/scans"
        className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-[0.1em] text-primary transition-colors hover:text-primary/80"
      >
        Go to Scans <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}

function ErrorState({ detail }: { detail: string }) {
  return (
    <div
      role="alert"
      className="card-elevated relative mt-4 flex flex-col items-center justify-center gap-4 overflow-hidden rounded-md px-6 py-16 text-center"
    >
      <span aria-hidden className="absolute left-0 top-0 h-px w-16 bg-destructive/80" />
      <div className="flex h-12 w-12 items-center justify-center rounded-[4px] bg-destructive/10 ring-1 ring-inset ring-destructive/30">
        <AlertCircle className="h-6 w-6 text-destructive" />
      </div>
      <div className="space-y-1.5">
        <h2 className="font-mono text-base font-semibold uppercase tracking-[0.08em] text-foreground">
          Dashboard unavailable
        </h2>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">
          {detail}
        </p>
      </div>
      <Link
        to="/scans"
        className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-[0.1em] text-primary transition-colors hover:text-primary/80"
      >
        Go to Scans <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}

function IncompleteState({
  detail,
  publishedAt,
}: {
  detail: string;
  publishedAt?: string;
}) {
  return (
    <div
      role="status"
      className="card-elevated relative mt-4 flex flex-col items-center justify-center gap-4 overflow-hidden rounded-md px-6 py-16 text-center"
    >
      <span aria-hidden className="absolute left-0 top-0 h-px w-16 bg-amber-400/80" />
      <div className="flex h-12 w-12 items-center justify-center rounded-[4px] bg-amber-400/10 ring-1 ring-inset ring-amber-400/30">
        <AlertCircle className="h-6 w-6 text-amber-300" />
      </div>
      <div className="space-y-1.5">
        <h2 className="font-mono text-base font-semibold uppercase tracking-[0.08em] text-foreground">
          Posture verdicts withheld
        </h2>
        <p className="mx-auto max-w-xl text-sm text-muted-foreground">{detail}</p>
        {publishedAt && (
          <p className="font-mono text-[11px] uppercase tracking-[0.08em] text-amber-200">
            Last complete published snapshot:{" "}
            {new Date(publishedAt).toLocaleString()}
          </p>
        )}
      </div>
      <Link
        to="/scans"
        className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-[0.1em] text-primary transition-colors hover:text-primary/80"
      >
        Review scan stages <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}

const ROW = "animate-fade-up";

export function Dashboard() {
  const statsQuery = useGraphStats();
  const findingsQuery = useFindings();
  const nodesQuery = useNodes();
  const scansQuery = useScans(20);
  const latestPublishedQuery = useLatestPublishedScan();
  const postureQuery = useProjectionState();

  const required = [
    ["graph statistics", statsQuery],
    ["published findings", findingsQuery],
    ["node inventory", nodesQuery],
    ["scan history", scansQuery],
    ["published scan", latestPublishedQuery],
    ["projection state", postureQuery],
  ] as const;
  const coldFailures = required.filter(
    ([, query]) => query.isError && query.data === undefined,
  );
  const cachedFailures = required.filter(
    ([, query]) => query.isError && query.data !== undefined,
  );
  const cachedAsOf =
    cachedFailures.length > 0
      ? Math.min(...cachedFailures.map(([, query]) => query.dataUpdatedAt))
      : 0;
  const isLoading =
    coldFailures.length === 0 &&
    required.some(([, query]) => query.isLoading);
  const stats = statsQuery.data;
  const scans = scansQuery.data ?? [];
  const posture = postureQuery.data;
  const latestPublished =
    latestPublishedQuery.data ?? latestPublishedScan(scans);
  const publishedStagesComplete =
    latestPublished != null &&
    latestPublished.collection_status === "complete" &&
    latestPublished.graph_status === "complete" &&
    latestPublished.analysis_status === "complete" &&
    latestPublished.snapshot_status === "complete" &&
    latestPublished.projection_status === "complete";
  const projectionIncomplete =
    posture?.status === "updating" || posture?.status === "incomplete";
  const unknownProjectionWithInventory =
    posture?.status === "unknown" && (stats?.total_nodes ?? 0) > 0;
  const missingPublishedSnapshot =
    (stats?.total_nodes ?? 0) > 0 &&
    (!posture?.published_scan_id || latestPublished == null);
  const publishedSnapshotIncomplete =
    latestPublished != null && !publishedStagesComplete;
  const matchingProjection = sameDashboardProjection(
    findingsQuery.snapshot?.scanId && findingsQuery.snapshot.revision != null
      ? {
          scanId: findingsQuery.snapshot.scanId,
          revision: findingsQuery.snapshot.revision,
        }
      : null,
    stats?.projection,
    nodesQuery.snapshot,
    latestPublished?.published_revision != null
      ? {
          scanId: latestPublished.id,
          revision: latestPublished.published_revision,
        }
      : null,
    posture?.published_scan_id && posture.published_revision != null
      ? {
          scanId: posture.published_scan_id,
          revision: posture.published_revision,
        }
      : null,
  );
  const projectionMismatch =
    findingsQuery.data !== undefined &&
    stats !== undefined &&
    nodesQuery.data !== undefined &&
    scansQuery.data !== undefined &&
    posture !== undefined &&
    !matchingProjection;
  const verdictsWithheld =
    !isLoading &&
    coldFailures.length === 0 &&
    (projectionIncomplete ||
      unknownProjectionWithInventory ||
      missingPublishedSnapshot ||
      publishedSnapshotIncomplete ||
      projectionMismatch);
  const isEmpty =
    !isLoading &&
    coldFailures.length === 0 &&
    !verdictsWithheld &&
    (stats?.total_nodes ?? 0) === 0;
  const errorDetail =
    coldFailures.length > 0
      ? `AgentHound could not load ${coldFailures
          .map(([name]) => name)
          .join(", ")}. Security posture conclusions are unavailable.`
      : "";
  const incompleteDetail = projectionIncomplete
    ? `The mutable graph projection is ${posture?.status}. Loaded graph values may be partial, so the dashboard will not calculate security verdicts.`
    : unknownProjectionWithInventory
      ? "Projection completeness is unknown for the loaded graph. Rescan before treating inventory or finding gaps as complete."
      : missingPublishedSnapshot
        ? "The loaded graph has no matching complete published scan snapshot. Mutable graph values cannot support dashboard verdicts."
        : projectionMismatch
          ? "Findings, graph inventory, scan history, and posture state do not identify the same published scan and revision. Mixed-revision data cannot support dashboard verdicts."
          : "The published scan lacks complete collection, graph, analysis, or snapshot evidence. Missing metadata is treated as unknown.";

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[1600px] space-y-3">
        <DashboardHeader />

        {cachedFailures.length > 0 && (
          <DataStateNotice tone="warning" title="Showing cached dashboard data">
            Refresh failed for{" "}
            {cachedFailures.map(([name]) => name).join(", ")}. Cached values are
            from {new Date(cachedAsOf).toLocaleString()} and may be stale.
          </DataStateNotice>
        )}

        <AsyncBoundary
          isLoading={isLoading}
          isError={coldFailures.length > 0}
          isEmpty={isEmpty}
          loading={
            <div className="card-elevated mt-4 flex h-56 items-center justify-center rounded-md font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
              Loading posture snapshot…
            </div>
          }
          error={<ErrorState detail={errorDetail} />}
          empty={<EmptyState />}
        >
          {verdictsWithheld ? (
            <IncompleteState
              detail={incompleteDetail}
              publishedAt={posture?.published_at}
            />
          ) : (
            <>
            <div className={ROW} style={{ animationDelay: "30ms" }}>
              <StatCards />
            </div>

            <div className={`grid gap-3 lg:grid-cols-3 ${ROW}`} style={{ animationDelay: "80ms" }}>
              <div className="lg:col-span-1">
                <ExposureGauge />
              </div>
              <div className="grid gap-3 lg:col-span-2">
                <SeverityRings />
                <InventoryTrend />
              </div>
            </div>

            <div className={`grid gap-3 lg:grid-cols-3 ${ROW}`} style={{ animationDelay: "130ms" }}>
              <div className="lg:col-span-2">
                <CategoryBreakdown />
              </div>
              <div className="lg:col-span-1">
                <AuthCoverage />
              </div>
            </div>

            <div className={`grid gap-3 lg:grid-cols-2 ${ROW}`} style={{ animationDelay: "180ms" }}>
              <TopRiskyEntities />
              <TopFindings />
            </div>

            <div className={`grid gap-3 lg:grid-cols-2 ${ROW}`} style={{ animationDelay: "230ms" }}>
              <CrossProtocol />
              <Chokepoints />
            </div>

            <div className={ROW} style={{ animationDelay: "280ms" }}>
              <RecentScans />
            </div>
            </>
          )}
        </AsyncBoundary>
      </div>
    </div>
  );
}

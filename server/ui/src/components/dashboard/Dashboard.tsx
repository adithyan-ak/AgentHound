import { Link } from "react-router-dom";
import { ScanSearch, ArrowRight } from "lucide-react";
import { useGraphStats } from "@/hooks/useGraph";
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

const ROW = "animate-fade-up";

export function Dashboard() {
  const { data: stats, isLoading } = useGraphStats();
  const isEmpty = !isLoading && (stats?.total_nodes ?? 0) === 0;

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[1600px] space-y-3">
        <DashboardHeader />

        {isEmpty ? (
          <EmptyState />
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
      </div>
    </div>
  );
}

import { lazy, Suspense } from "react";
import { Routes, Route, Link } from "react-router-dom";
import { RouteOff } from "lucide-react";
import { AppLayout } from "./layout";
import { Dashboard } from "@features/dashboard";
import { ScanManager } from "@features/scans";
import { QueryLibrary } from "@features/queries";
import { RulesLibrary } from "@features/rules";

const ExplorerPage = lazy(() =>
  import("@features/explorer").then((m) => ({
    default: m.ExplorerPage,
  })),
);

const FindingsListPage = lazy(() =>
  import("@features/findings/ui/FindingsListPage").then((m) => ({
    default: m.FindingsListPage,
  })),
);

const FindingDetailPage = lazy(() =>
  import("@features/findings/ui/FindingDetailPage").then((m) => ({
    default: m.FindingDetailPage,
  })),
);

function ExplorerFallback() {
  return (
    <div className="flex h-full items-center justify-center">
      <p className="text-sm text-muted-foreground">Loading Explorer…</p>
    </div>
  );
}

export function NotFoundPage() {
  return (
    <div className="dashboard-bg flex min-h-full items-center justify-center p-6">
      <div
        role="alert"
        className="card-elevated flex max-w-md flex-col items-center gap-3 rounded-md px-8 py-10 text-center"
      >
        <RouteOff className="h-8 w-8 text-amber-300" aria-hidden />
        <h1 className="font-mono text-lg font-semibold uppercase tracking-[0.08em] text-foreground">
          Route not found
        </h1>
        <p className="text-sm text-muted-foreground">
          This AgentHound page does not exist.
        </p>
        <Link
          to="/"
          className="font-mono text-xs uppercase tracking-[0.1em] text-primary hover:text-primary/80"
        >
          Return to dashboard
        </Link>
      </div>
    </div>
  );
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route
          path="/explorer"
          element={
            <Suspense fallback={<ExplorerFallback />}>
              <ExplorerPage />
            </Suspense>
          }
        />
        <Route
          path="/findings"
          element={
            <Suspense fallback={<div className="flex h-full items-center justify-center"><p className="text-sm text-muted-foreground">Loading Findings…</p></div>}>
              <FindingsListPage />
            </Suspense>
          }
        />
        <Route
          path="/findings/:findingId"
          element={
            <Suspense fallback={<div className="flex h-full items-center justify-center"><p className="text-sm text-muted-foreground">Loading Finding…</p></div>}>
              <FindingDetailPage />
            </Suspense>
          }
        />

        <Route path="/scans" element={<ScanManager />} />
        <Route path="/queries" element={<QueryLibrary />} />
        <Route path="/rules" element={<RulesLibrary />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

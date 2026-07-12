import { lazy, Suspense } from "react";
import { Routes, Route, Link, useLocation } from "react-router-dom";
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

// Catch-all for unknown client routes. Without it, a deep link / typo / stale
// bookmark renders a blank layout with no feedback. Kept inside AppLayout so
// the nav stays available and the user can recover.
function NotFound() {
  const location = useLocation();
  return (
    <div
      role="alert"
      className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center"
    >
      <p className="font-mono text-sm font-semibold uppercase tracking-[0.12em] text-foreground">
        Page not found
      </p>
      <p className="max-w-md text-sm text-muted-foreground">
        No view is mapped to{" "}
        <code className="font-mono text-foreground/80">{location.pathname}</code>.
      </p>
      <Link
        to="/"
        className="font-mono text-xs uppercase tracking-[0.08em] text-primary transition-colors hover:text-primary/80"
      >
        ▸ Back to Dashboard
      </Link>
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

        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

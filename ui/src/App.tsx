import { lazy, Suspense, useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { Dashboard } from "@/components/dashboard/Dashboard";
import { GraphExplorer } from "@/components/graph/GraphExplorer";
import { ScanManager } from "@/components/scans/ScanManager";
import { QueryLibrary } from "@/components/queries/QueryLibrary";
import { LoginPage } from "@/components/auth/LoginPage";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { useAuthStore } from "@/store/auth";

const ExplorerPage = lazy(() =>
  import("@/components/explorer/ExplorerPage").then((m) => ({
    default: m.ExplorerPage,
  })),
);

function ExplorerFallback() {
  return (
    <div className="flex h-full items-center justify-center">
      <p className="text-sm text-muted-foreground">Loading Explorer…</p>
    </div>
  );
}

export function App() {
  const initialize = useAuthStore((s) => s.initialize);

  useEffect(() => {
    initialize();
  }, [initialize]);

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/graph" element={<GraphExplorer />} />
          <Route
            path="/explorer"
            element={
              <Suspense fallback={<ExplorerFallback />}>
                <ExplorerPage />
              </Suspense>
            }
          />
          <Route path="/pathfinder" element={<Navigate to="/graph" replace />} />
          <Route path="/scans" element={<ScanManager />} />
          <Route path="/queries" element={<QueryLibrary />} />
        </Route>
      </Route>
    </Routes>
  );
}

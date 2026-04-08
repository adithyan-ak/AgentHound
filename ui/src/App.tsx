import { Routes, Route } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { Dashboard } from "@/components/dashboard/Dashboard";
import { GraphExplorer } from "@/components/graph/GraphExplorer";
import { Pathfinder } from "@/components/pathfinder/Pathfinder";
import { ScanManager } from "@/components/scans/ScanManager";
import { QueryLibrary } from "@/components/queries/QueryLibrary";

export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/graph" element={<GraphExplorer />} />
        <Route path="/pathfinder" element={<Pathfinder />} />
        <Route path="/scans" element={<ScanManager />} />
        <Route path="/queries" element={<QueryLibrary />} />
      </Route>
    </Routes>
  );
}
